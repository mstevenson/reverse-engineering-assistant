/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.tools.data;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Content;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.tools.AbstractToolProvider;
import reva.tools.ProgramValidationException;
import reva.util.AddressUtil;
import reva.util.DataTypeParserUtil;

/**
 * Tool provider for accessing data at specific addresses or by symbol names in programs.
 */
public class DataToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public DataToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerGetDataTool();
        registerApplyDataTypeTool();
        registerApplyEnumTool();
        registerSetEquateTool();
        registerCreateLabelTool();
    }

    /**
     * Register a unified tool to get data by address or symbol name
     */
    private void registerGetDataTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the data"
        ));
        properties.put("addressOrSymbol", Map.of(
            "type", "string",
            "description", "Address or symbol name to get data from (e.g., '0x00400000' or 'main')"
        ));

        List<String> required = List.of("programPath", "addressOrSymbol");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-data")
            .title("Get Data")
            .description("Get data at a specific address or symbol in a program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and address using helper methods
            Program program = getProgramFromArgs(request);
            Address address = getAddressFromArgs(request, program, "addressOrSymbol");

            return getDataAtAddressResult(program, address);
        });
    }

    /**
     * Register a tool to apply a data type to an address or symbol
     */
    private void registerApplyDataTypeTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("addressOrSymbol", Map.of(
            "type", "string",
            "description", "Address or symbol name to apply the data type to (e.g., '0x00400000' or 'main')"
        ));
        properties.put("dataTypeString", Map.of(
            "type", "string",
            "description", "String representation of the data type (e.g., 'char**', 'int[10]')"
        ));
        properties.put("archiveName", Map.of(
            "type", "string",
            "description", "Optional name of the data type archive to search in. If not provided, all archives will be searched.",
            "default", ""
        ));

        List<String> required = List.of("programPath", "addressOrSymbol", "dataTypeString");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("apply-data-type")
            .title("Apply Data Type")
            .description("Apply a data type to a specific address or symbol in a program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program = getProgramFromArgs(request);
            Address targetAddress = getAddressFromArgs(request, program, "addressOrSymbol");
            String dataTypeString = getString(request, "dataTypeString");
            String archiveName = getOptionalString(request, "archiveName", "");

            if (dataTypeString.trim().isEmpty()) {
                return createErrorResult("Data type string cannot be empty");
            }

            try {
                // Try to parse the data type from the string and get the actual DataType object
                DataType dataType;
                try {
                    dataType = DataTypeParserUtil.parseDataTypeObjectFromString(dataTypeString, archiveName);
                    if (dataType == null) {
                        return createErrorResult("Could not find data type: " + dataTypeString +
                            ". Try using the get-data-type-archives and get-data-types tools to find available data types.");
                    }
                } catch (Exception e) {
                    return createErrorResult("Error parsing data type: " + e.getMessage() +
                        ". Try using the get-data-type-archives and get-data-types tools to find available data types.");
                }

                // Start a transaction to apply the data type
                int transactionID = program.startTransaction("Apply Data Type");
                boolean success = false;

                try {

                    // Get the listing and apply the data type at the symbol's address
                    Listing listing = program.getListing();

                    // Clear any existing data at the address
                    if (listing.getDataAt(targetAddress) != null) {
                        if (dataType.getLength() > 0) {
                            listing.clearCodeUnits(targetAddress, targetAddress.add(dataType.getLength() - 1), false);
                        } else {
                            listing.clearCodeUnits(targetAddress, targetAddress, false);
                        }
                    }

                    // Create the data at the address with the specified data type
                    Data createdData = listing.createData(targetAddress, dataType);

                    if (createdData == null) {
                        throw new Exception("Failed to create data at address: " + targetAddress);
                    }

                    success = true;

                    // Create result data
                    Map<String, Object> resultData = new HashMap<>();
                    resultData.put("success", true);
                    resultData.put("address", AddressUtil.formatAddress(targetAddress));
                    resultData.put("dataType", dataType.getName());
                    resultData.put("dataTypeDisplayName", dataType.getDisplayName());
                    resultData.put("length", dataType.getLength());

                    return createJsonResult(resultData);
                } finally {
                    // End transaction
                    program.endTransaction(transactionID, success);
                }
            } catch (Exception e) {
                return createErrorResult("Error applying data type to symbol: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to apply an enum datatype to an address or symbol.
     */
    private void registerApplyEnumTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("addressOrSymbol", Map.of(
            "type", "string",
            "description", "Address or symbol name to apply the enum to"
        ));
        properties.put("enumName", Map.of(
            "type", "string",
            "description", "Name of the enum datatype to apply"
        ));
        properties.put("archiveName", Map.of(
            "type", "string",
            "description", "Optional data type archive to search first.",
            "default", ""
        ));
        properties.put("clearExisting", Map.of(
            "type", "boolean",
            "description", "Clear existing data before applying the enum",
            "default", true
        ));

        List<String> required = List.of("programPath", "addressOrSymbol", "enumName");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("apply-enum")
            .title("Apply Enum")
            .description("Apply an enum datatype to a specific address or symbol in a program")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address targetAddress = getAddressFromArgs(request, program, "addressOrSymbol");
            String enumName = getString(request, "enumName");
            String archiveName = getOptionalString(request, "archiveName", "");
            boolean clearExisting = getOptionalBoolean(request, "clearExisting", true);

            try {
                DataType dt = DataTypeParserUtil.parseDataTypeObjectFromString(enumName, archiveName);
                if (dt == null) {
                    return createErrorResult("Could not find enum datatype: " + enumName);
                }
                if (!(dt instanceof Enum enumDt)) {
                    return createErrorResult("Data type is not an enum: " + enumName);
                }

                return applyDataTypeAtAddress(program, targetAddress, enumDt, clearExisting, "apply enum");
            } catch (Exception e) {
                return createErrorResult("Error applying enum: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to set an equate reference on an instruction operand.
     */
    private void registerSetEquateTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("addressOrSymbol", Map.of(
            "type", "string",
            "description", "Instruction address or symbol name where the equate should be applied"
        ));
        properties.put("operandIndex", Map.of(
            "type", "integer",
            "description", "Instruction operand index to annotate"
        ));
        properties.put("equateName", Map.of(
            "type", "string",
            "description", "Equate name to create or reuse"
        ));
        properties.put("value", Map.of(
            "description", "Equate value (decimal, hex like 0x10, or negative)",
            "anyOf", List.of(
                Map.of("type", "integer"),
                Map.of("type", "string")
            )
        ));
        properties.put("replaceExisting", Map.of(
            "type", "boolean",
            "description", "Remove any existing equates from the operand before applying this one",
            "default", false
        ));

        List<String> required = List.of("programPath", "addressOrSymbol", "operandIndex", "equateName", "value");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("set-equate")
            .title("Set Equate")
            .description("Create or reuse an equate and attach it to a specific instruction operand")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                Address address = getAddressFromArgs(request, program, "addressOrSymbol");
                int operandIndex = getInt(request, "operandIndex");
                String equateName = getString(request, "equateName");
                long value = parseFlexibleLong(request.arguments().get("value"), "value");
                boolean replaceExisting = getOptionalBoolean(request, "replaceExisting", false);

                Listing listing = program.getListing();
                Instruction instruction = listing.getInstructionAt(address);
                if (instruction == null) {
                    return createErrorResult("No instruction found at address: " + AddressUtil.formatAddress(address));
                }
                if (operandIndex < 0 || operandIndex >= instruction.getNumOperands()) {
                    return createErrorResult("Operand index out of range: " + operandIndex);
                }

                EquateTable equateTable = program.getEquateTable();

                int transactionID = program.startTransaction("Set Equate");
                boolean success = false;
                try {
                    if (replaceExisting) {
                        for (Equate existing : equateTable.getEquates(address, operandIndex)) {
                            existing.removeReference(address, operandIndex);
                        }
                    }

                    Equate equate = equateTable.getEquate(equateName);
                    if (equate == null) {
                        equate = equateTable.createEquate(equateName, value);
                    } else if (equate.getValue() != value) {
                        throw new IllegalArgumentException(
                            "Equate name already exists with different value: " + equateName);
                    }

                    equate.addReference(address, operandIndex);
                    success = true;

                    Map<String, Object> resultData = new HashMap<>();
                    resultData.put("success", true);
                    resultData.put("address", AddressUtil.formatAddress(address));
                    resultData.put("operandIndex", operandIndex);
                    resultData.put("equateName", equate.getName());
                    resultData.put("value", equate.getValue());
                    resultData.put("displayValue", equate.getDisplayValue());
                    resultData.put("referenceCount", equate.getReferenceCount());
                    return createJsonResult(resultData);
                } catch (DuplicateNameException | InvalidInputException e) {
                    return createErrorResult("Error setting equate: " + e.getMessage());
                } catch (Exception e) {
                    return createErrorResult("Error setting equate: " + e.getMessage());
                } finally {
                    program.endTransaction(transactionID, success);
                }
            } catch (Exception e) {
                return createErrorResult("Error setting equate: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to create a label at a specific address in a program
     */
    private void registerCreateLabelTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program containing the address"
        ));
        properties.put("addressOrSymbol", Map.of(
            "type", "string",
            "description", "Address or symbol name to create label at (e.g., '0x00400000' or 'main')"
        ));
        properties.put("labelName", Map.of(
            "type", "string",
            "description", "Name for the label to create"
        ));
        properties.put("setAsPrimary", Map.of(
            "type", "boolean",
            "description", "Whether to set this label as primary if other labels exist at the address",
            "default", true
        ));

        List<String> required = List.of("programPath", "addressOrSymbol", "labelName");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("create-label")
            .title("Create Label")
            .description("Create a label at a specific address in a program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get program and parameters using helper methods
            Program program;
            String labelName;
            Address address;
            try {
                program = getProgramFromArgs(request);
                labelName = getString(request, "labelName");
                address = getAddressFromArgs(request, program, "addressOrSymbol");
            } catch (IllegalArgumentException | ProgramValidationException e) {
                return createErrorResult(e.getMessage());
            }
            boolean setAsPrimary = getOptionalBoolean(request, "setAsPrimary", true);

            if (labelName.trim().isEmpty()) {
                return createErrorResult("Label name cannot be empty");
            }

            // Start a transaction to create the label
            int transactionID = program.startTransaction("Create Label");
            boolean success = false;

            try {
                // Get the symbol table
                SymbolTable symbolTable = program.getSymbolTable();

                // Create the label
                Symbol symbol = symbolTable.createLabel(address, labelName,
                    program.getGlobalNamespace(), ghidra.program.model.symbol.SourceType.USER_DEFINED);

                if (symbol == null) {
                    throw new Exception("Failed to create label at address: " + address);
                }

                // Set the label as primary if requested
                if (setAsPrimary && !symbol.isPrimary()) {
                    symbol.setPrimary();
                }

                success = true;

                // Create result data
                Map<String, Object> resultData = new HashMap<>();
                resultData.put("success", true);
                resultData.put("labelName", labelName);
                resultData.put("address", AddressUtil.formatAddress(address));
                resultData.put("isPrimary", symbol.isPrimary());

                return createJsonResult(resultData);
            } catch (Exception e) {
                return createErrorResult("Error creating label: " + e.getMessage());
            } finally {
                // End transaction
                program.endTransaction(transactionID, success);
            }
        });
    }

    /**
     * Helper method to get data at a specific address and format the result
     * @param program The program to look up data in
     * @param address The address where to find data
     * @return Call tool result with data information
     */
    private CallToolResult getDataAtAddressResult(Program program, Address address) {

        // Get data at or containing the address
        Data data = AddressUtil.getContainingData(program, address);
        if (data == null) {
            return createErrorResult("No data found at address: " + AddressUtil.formatAddress(address));
        }

        // Create result data
        Map<String, Object> resultData = new HashMap<>();
        resultData.put("programPath", program.getDomainFile().getPathname());
        resultData.put("address", AddressUtil.formatAddress(data.getAddress()));
        resultData.put("dataType", data.getDataType().getName());
        resultData.put("length", data.getLength());

        // Check if the address is for a symbol
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol primarySymbol = symbolTable.getPrimarySymbol(data.getAddress());
        if (primarySymbol != null) {
            resultData.put("symbolName", primarySymbol.getName());
            resultData.put("symbolNamespace", primarySymbol.getParentNamespace().getName());
        }

        // Get the bytes and convert to hex
        StringBuilder hexString = new StringBuilder();
        try {
            byte[] bytes = data.getBytes();
            for (byte b : bytes) {
                hexString.append(String.format("%02x", b & 0xff));
            }
            resultData.put("hexBytes", hexString.toString());
        } catch (MemoryAccessException e) {
            resultData.put("hexBytesError", "Memory access error: " + e.getMessage());
        }

        // Get the string representation that would be shown in the listing
        String representation = data.getDefaultValueRepresentation();
        resultData.put("representation", representation);

        // Get the value object
        Object value = data.getValue();
        if (value != null) {
            resultData.put("valueType", value.getClass().getSimpleName());
            resultData.put("value", value.toString());
        } else {
            resultData.put("value", null);
        }

        try {
            List<Content> contents = new ArrayList<>();
            contents.add(new TextContent(JSON.writeValueAsString(resultData)));
            return CallToolResult.builder().content(contents).isError(false).build();
        } catch (JsonProcessingException e) {
            return createErrorResult("Error converting data to JSON: " + e.getMessage());
        }
    }

    private CallToolResult applyDataTypeAtAddress(Program program, Address targetAddress, DataType dataType,
        boolean clearExisting, String operationName) {
        int transactionID = program.startTransaction("Apply Data Type");
        boolean success = false;

        try {
            Listing listing = program.getListing();

            if (clearExisting && listing.getDataAt(targetAddress) != null) {
                if (dataType.getLength() > 0) {
                    listing.clearCodeUnits(targetAddress, targetAddress.add(dataType.getLength() - 1), false);
                } else {
                    listing.clearCodeUnits(targetAddress, targetAddress, false);
                }
            }

            Data createdData = listing.createData(targetAddress, dataType);
            if (createdData == null) {
                throw new Exception("Failed to create data at address: " + targetAddress);
            }

            success = true;

            Map<String, Object> resultData = new HashMap<>();
            resultData.put("success", true);
            resultData.put("address", AddressUtil.formatAddress(targetAddress));
            resultData.put("dataType", dataType.getName());
            resultData.put("dataTypeDisplayName", dataType.getDisplayName());
            resultData.put("length", dataType.getLength());
            resultData.put("operation", operationName);

            return createJsonResult(resultData);
        } catch (Exception e) {
            return createErrorResult("Error during " + operationName + ": " + e.getMessage());
        } finally {
            program.endTransaction(transactionID, success);
        }
    }

    private long parseFlexibleLong(Object value, String key) {
        if (value == null) {
            throw new IllegalArgumentException("Missing required parameter: " + key);
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String str) {
            try {
                return Long.decode(str);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Parameter '" + key + "' must be a number, got: " + value);
            }
        }
        throw new IllegalArgumentException("Parameter '" + key + "' must be a number");
    }
}
