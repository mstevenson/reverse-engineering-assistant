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
package reva.tools.structures;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.DataTypeParserUtil;
import reva.util.SchemaUtil;

/**
 * Tool provider for structure definition and manipulation operations.
 * Provides tools to create, modify, and apply structures in Ghidra programs.
 */
public class StructureToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public StructureToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerParseCStructureTool();
        registerValidateCStructureTool();
        registerGetStructureInfoTool();
        registerListStructuresTool();
        registerApplyStructureTool();
        registerRenameStructureComponentTool();
        registerSetStructureComponentTypeTool();
        registerDeleteStructureTool();
        registerParseCHeaderTool();
    }

    /**
     * Register tool to parse C-style structure definitions (create-or-replace)
     */
    private void registerParseCStructureTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("cDefinition", SchemaUtil.createStringProperty("C-style structure definition"));
        properties.put("category", SchemaUtil.createOptionalStringProperty("Category path (default: /)"));

        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("cDefinition");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("parse-c-structure")
            .title("Parse C Structure")
            .description("Parse and create or replace a structure from a C-style definition. " +
                         "If a structure with the same name already exists, it will be replaced " +
                         "with the new definition (fields are completely rebuilt). " +
                         "Use get-structure-info to see the current layout before modifying.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String cDefinition = getString(request, "cDefinition");
                String category = getOptionalString(request, "category", "/");

                DataTypeManager dtm = program.getDataTypeManager();
                CParser cparser = new CParser(dtm);

                int txId = program.startTransaction("Parse C Structure");
                try {
                    DataType dt = cparser.parse(cDefinition);
                    if (dt == null) {
                        throw new Exception("Failed to parse structure definition");
                    }

                    String structName = dt.getName();

                    // Check if a structure with this name already exists
                    DataType existingDt = findDataTypeByName(dtm, structName);
                    if (existingDt != null && existingDt instanceof Structure && dt instanceof Structure) {
                        // Replace existing structure: clear fields and rebuild
                        Structure existingStruct = (Structure) existingDt;
                        Structure parsedStruct = (Structure) dt;

                        // Set packing before adding components so layout is correct
                        existingStruct.setPackingEnabled(parsedStruct.isPackingEnabled());

                        // Clear all existing components
                        existingStruct.deleteAll();

                        // Add all defined components from the parsed structure
                        for (DataTypeComponent comp : parsedStruct.getDefinedComponents()) {
                            DataType fieldType = comp.getDataType();

                            // Resolve the field type in the program's DTM
                            fieldType = dtm.resolve(fieldType, DataTypeConflictHandler.DEFAULT_HANDLER);

                            if (comp.isBitFieldComponent()) {
                                BitFieldDataType bitfield = (BitFieldDataType) fieldType;
                                existingStruct.addBitField(
                                    bitfield.getBaseDataType(),
                                    bitfield.getBitSize(),
                                    comp.getFieldName(),
                                    comp.getComment()
                                );
                            } else if (existingStruct.isPackingEnabled()) {
                                existingStruct.add(fieldType, comp.getLength(),
                                    comp.getFieldName(), comp.getComment());
                            } else {
                                existingStruct.insertAtOffset(comp.getOffset(), fieldType,
                                    comp.getLength(), comp.getFieldName(), comp.getComment());
                            }
                        }

                        // Copy properties
                        if (parsedStruct.getDescription() != null) {
                            existingStruct.setDescription(parsedStruct.getDescription());
                        }

                        // Apply category if specified
                        CategoryPath catPath = new CategoryPath(category);
                        if (!existingStruct.getCategoryPath().equals(catPath)) {
                            Category cat = dtm.createCategory(catPath);
                            if (cat != null) {
                                cat.moveDataType(existingStruct, DataTypeConflictHandler.REPLACE_HANDLER);
                            }
                        }

                        program.endTransaction(txId, true);

                        Map<String, Object> result = createDetailedStructureInfo(existingStruct);
                        result.put("message", "Successfully modified structure from C definition: " + structName);
                        result.put("numComponents", existingStruct.getNumDefinedComponents());
                        return createJsonResult(result);
                    } else {
                        // New structure or replacing non-structure: resolve into DTM
                        CategoryPath catPath = new CategoryPath(category);
                        Category cat = dtm.createCategory(catPath);

                        DataType resolved = dtm.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                        if (cat != null && !resolved.getCategoryPath().equals(catPath)) {
                            cat.moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
                        }

                        program.endTransaction(txId, true);

                        Map<String, Object> result = (resolved instanceof Composite)
                            ? createDetailedStructureInfo((Composite) resolved)
                            : createStructureInfo(resolved);
                        result.put("message", "Successfully created structure: " + resolved.getName());
                        return createJsonResult(result);
                    }

                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to parse C structure", e);
                    return createErrorResult("Failed to parse: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to validate C-style structure definitions without creating them
     */
    private void registerValidateCStructureTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("cDefinition", SchemaUtil.createStringProperty("C-style structure definition to validate"));

        List<String> required = new ArrayList<>();
        required.add("cDefinition");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("validate-c-structure")
            .title("Validate C Structure")
            .description("Validate C-style structure definition without creating it")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                String cDefinition = getString(request, "cDefinition");

                // Create a temporary parser with a standalone DTM
                DataTypeManager tempDtm = new StandAloneDataTypeManager("temp");
                CParser parser = new CParser(tempDtm);

                try {
                    DataType dt = parser.parse(cDefinition);
                    if (dt == null) {
                        return createErrorResult("Invalid structure definition");
                    }

                    Map<String, Object> result = new HashMap<>();
                    result.put("valid", true);
                    result.put("parsedType", dt.getName());
                    result.put("displayName", dt.getDisplayName());
                    result.put("size", dt.getLength());

                    if (dt instanceof Structure) {
                        Structure struct = (Structure) dt;
                        result.put("fieldCount", struct.getNumComponents());
                        result.put("isUnion", false);
                    } else if (dt instanceof Union) {
                        Union union = (Union) dt;
                        result.put("fieldCount", union.getNumComponents());
                        result.put("isUnion", true);
                    }

                    return createJsonResult(result);

                } catch (Exception e) {
                    Map<String, Object> result = new HashMap<>();
                    result.put("valid", false);
                    result.put("error", e.getMessage());
                    return createJsonResult(result);
                } finally {
                    tempDtm.close();
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to get structure information
     */
    private void registerGetStructureInfoTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure"));

        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("structureName");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-structure-info")
            .title("Get Structure Info")
            .description("Get detailed information about a structure or union, including a C representation of its layout")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String structureName = getString(request, "structureName");

                DataTypeManager dtm = program.getDataTypeManager();
                DataType dt = findDataTypeByName(dtm, structureName);

                if (dt == null) {
                    return createErrorResult("Structure not found: " + structureName);
                }

                if (!(dt instanceof Composite)) {
                    return createErrorResult("Data type is not a structure or union: " + structureName);
                }

                return createJsonResult(createDetailedStructureInfo((Composite) dt));

            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to list structures
     */
    private void registerListStructuresTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("category", SchemaUtil.createOptionalStringProperty("Filter by category path"));
        properties.put("nameFilter", SchemaUtil.createOptionalStringProperty("Filter by name (substring match)"));
        properties.put("includeBuiltIn", SchemaUtil.createOptionalBooleanProperty("Include built-in types (default: false)"));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based)",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Maximum number of structures to return",
            "default", 100
        ));

        List<String> required = new ArrayList<>();
        required.add("programPath");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-structures")
            .title("List Structures")
            .description("List structures and unions in a program with optional filtering and pagination")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String categoryFilter = getOptionalString(request, "category", null);
                String nameFilter = getOptionalString(request, "nameFilter", null);
                boolean includeBuiltIn = getOptionalBoolean(request, "includeBuiltIn", false);
                PaginationParams pagination = getPaginationParams(request, 100);

                DataTypeManager dtm = program.getDataTypeManager();
                List<Map<String, Object>> structures = new ArrayList<>();
                int matchIndex = 0;
                int totalMatches = 0;

                // Get all data types
                Iterator<DataType> iter = dtm.getAllDataTypes();
                while (iter.hasNext()) {
                    DataType dt = iter.next();
                    if (!(dt instanceof Composite)) {
                        continue;
                    }

                    // Apply filters
                    if (!includeBuiltIn && dt.getSourceArchive() != null
                        && dt.getSourceArchive().getName().equals("BuiltInTypes")) {
                        continue;
                    }

                    if (categoryFilter != null &&
                        !dt.getCategoryPath().getPath().startsWith(categoryFilter)) {
                        continue;
                    }

                    if (nameFilter != null &&
                        !dt.getName().toLowerCase().contains(nameFilter.toLowerCase())) {
                        continue;
                    }

                    totalMatches++;

                    // Apply pagination
                    if (matchIndex >= pagination.startIndex()
                        && structures.size() < pagination.maxCount()) {
                        structures.add(createStructureInfo(dt));
                    }
                    matchIndex++;
                }

                Map<String, Object> result = new HashMap<>();
                result.put("structures", structures);
                Map<String, Object> paginationInfo = new HashMap<>();
                paginationInfo.put("startIndex", pagination.startIndex());
                paginationInfo.put("requestedCount", pagination.maxCount());
                paginationInfo.put("returnedCount", structures.size());
                paginationInfo.put("totalCount", totalMatches);
                paginationInfo.put("nextStartIndex", pagination.startIndex() + structures.size());
                result.put("pagination", paginationInfo);

                return createJsonResult(result);

            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to apply structure at address
     */
    private void registerApplyStructureTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure"));
        properties.put("addressOrSymbol", SchemaUtil.createStringProperty("Address or symbol name to apply structure"));
        properties.put("clearExisting", SchemaUtil.createOptionalBooleanProperty("Clear existing data"));

        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("structureName");
        required.add("addressOrSymbol");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("apply-structure")
            .title("Apply Structure")
            .description("Apply a structure at a specific address")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String structureName = getString(request, "structureName");
                Address address = getAddressFromArgs(request, program, "addressOrSymbol");
                boolean clearExisting = getOptionalBoolean(request, "clearExisting", true);

                DataTypeManager dtm = program.getDataTypeManager();
                DataType dt = findDataTypeByName(dtm, structureName);

                if (dt == null) {
                    return createErrorResult("Structure not found: " + structureName);
                }

                if (!(dt instanceof Composite)) {
                    return createErrorResult("Data type is not a structure or union: " + structureName);
                }

                // Check if address is in valid memory
                Memory memory = program.getMemory();
                if (!memory.contains(address)) {
                    return createErrorResult("Address is not in valid memory: " + AddressUtil.formatAddress(address));
                }

                int txId = program.startTransaction("Apply Structure");
                try {
                    Listing listing = program.getListing();

                    if (clearExisting) {
                        // Clear existing data
                        Data existingData = listing.getDataAt(address);
                        if (existingData != null) {
                            listing.clearCodeUnits(address, address.add(existingData.getLength() - 1), false);
                        }
                    }

                    // Create data
                    Data data = listing.createData(address, dt);

                    program.endTransaction(txId, true);

                    Map<String, Object> result = new HashMap<>();
                    result.put("message", "Successfully applied structure at " + AddressUtil.formatAddress(address));
                    result.put("address", AddressUtil.formatAddress(address));
                    result.put("structureName", dt.getName());
                    result.put("size", data.getLength());

                    return createJsonResult(result);

                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to apply structure", e);
                    return createErrorResult("Failed to apply structure: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }


    /**
     * Register tool to rename or update a single structure/union component in place.
     */
    private void registerRenameStructureComponentTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure or union"));
        properties.put("fieldName", SchemaUtil.createOptionalStringProperty("Existing field name to match"));
        properties.put("ordinal", Map.of(
            "type", "integer",
            "description", "Component ordinal to rename (0-based)"
        ));
        properties.put("offset", SchemaUtil.createOptionalStringProperty(
            "Component offset to rename (decimal or hex like 0x2e)"));
        properties.put("newFieldName", SchemaUtil.createStringProperty("New field name"));
        properties.put("newComment", SchemaUtil.createOptionalStringProperty("Optional new comment for the component"));

        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("structureName");
        required.add("newFieldName");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("rename-structure-component")
            .title("Rename Structure Component")
            .description("Rename a single structure or union component in place without rebuilding the full datatype. " +
                         "Select the component by fieldName, ordinal, or offset. Optionally update its comment.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String structureName = getString(request, "structureName");
                String fieldName = getOptionalString(request, "fieldName", null);
                Integer ordinal = getOptionalInteger(request.arguments(), "ordinal", null);
                String offsetString = getOptionalString(request, "offset", null);
                String newFieldName = getString(request, "newFieldName");
                String newComment = getOptionalString(request, "newComment", null);

                int selectors = 0;
                if (fieldName != null && !fieldName.isBlank()) selectors++;
                if (ordinal != null) selectors++;
                if (offsetString != null && !offsetString.isBlank()) selectors++;
                if (selectors != 1) {
                    return createErrorResult("Specify exactly one selector: fieldName, ordinal, or offset");
                }

                DataTypeManager dtm = program.getDataTypeManager();
                DataType dt = findDataTypeByName(dtm, structureName);
                if (dt == null) {
                    return createErrorResult("Structure not found: " + structureName);
                }
                if (!(dt instanceof Composite composite)) {
                    return createErrorResult("Data type is not a structure or union: " + structureName);
                }

                DataTypeComponent component = null;
                if (fieldName != null && !fieldName.isBlank()) {
                    for (DataTypeComponent comp : composite.getDefinedComponents()) {
                        if (fieldName.equals(comp.getFieldName())) {
                            component = comp;
                            break;
                        }
                    }
                    if (component == null) {
                        return createErrorResult("Component not found by fieldName: " + fieldName);
                    }
                }
                else if (ordinal != null) {
                    if (ordinal < 0 || ordinal >= composite.getNumComponents()) {
                        return createErrorResult("Ordinal out of range: " + ordinal);
                    }
                    component = composite.getComponent(ordinal);
                    if (component == null) {
                        return createErrorResult("Component not found at ordinal: " + ordinal);
                    }
                }
                else {
                    int offset;
                    try {
                        offset = Integer.decode(offsetString);
                    } catch (NumberFormatException e) {
                        return createErrorResult("Invalid offset: " + offsetString);
                    }
                    if (composite instanceof Structure struct) {
                        component = struct.getComponentAt(offset);
                    }
                    else if (composite instanceof Union) {
                        for (DataTypeComponent comp : composite.getDefinedComponents()) {
                            if (comp.getOffset() == offset) {
                                component = comp;
                                break;
                            }
                        }
                    }
                    if (component == null) {
                        return createErrorResult("Component not found at offset: " + offsetString);
                    }
                }

                String oldFieldName = component.getFieldName();
                String oldComment = component.getComment();

                int txId = program.startTransaction("Rename Structure Component");
                try {
                    component.setFieldName(newFieldName);
                    if (request.arguments().containsKey("newComment")) {
                        component.setComment(newComment);
                    }

                    program.endTransaction(txId, true);

                    Map<String, Object> result = new HashMap<>();
                    result.put("message", "Successfully updated component in structure: " + structureName);
                    result.put("structureName", composite.getName());
                    result.put("isUnion", composite instanceof Union);

                    Map<String, Object> componentInfo = new HashMap<>();
                    componentInfo.put("ordinal", component.getOrdinal());
                    componentInfo.put("offset", component.getOffset());
                    componentInfo.put("length", component.getLength());
                    componentInfo.put("oldFieldName", oldFieldName);
                    componentInfo.put("newFieldName", component.getFieldName());
                    componentInfo.put("dataType", component.getDataType().getDisplayName());
                    componentInfo.put("oldComment", oldComment);
                    componentInfo.put("newComment", component.getComment());
                    result.put("component", componentInfo);
                    result.put("structure", createDetailedStructureInfo(composite));
                    return createJsonResult(result);
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to rename structure component", e);
                    return createErrorResult("Failed to rename structure component: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }


    /**
     * Register tool to update a single structure component's datatype in place.
     */
    private void registerSetStructureComponentTypeTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure"));
        properties.put("fieldName", SchemaUtil.createOptionalStringProperty("Existing field name to match"));
        properties.put("ordinal", Map.of(
            "type", "integer",
            "description", "Component ordinal to update (0-based)"
        ));
        properties.put("offset", SchemaUtil.createOptionalStringProperty(
            "Component offset to update (decimal or hex like 0x2e)"));
        properties.put("dataType", SchemaUtil.createStringProperty(
            "New datatype string (e.g. short, pointer, Car *, int[4])"));
        properties.put("archiveName", SchemaUtil.createOptionalStringProperty(
            "Optional data type archive to search first"));
        properties.put("newFieldName", SchemaUtil.createOptionalStringProperty(
            "Optional replacement field name; defaults to existing field name"));
        properties.put("newComment", SchemaUtil.createOptionalStringProperty(
            "Optional replacement comment; defaults to existing comment"));

        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("structureName");
        required.add("dataType");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("set-structure-component-type")
            .title("Set Structure Component Type")
            .description("Update a single structure component's datatype in place without rebuilding the full datatype. " +
                         "Select the component by fieldName, ordinal, or offset. Preserves layout-sensitive structures.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String structureName = getString(request, "structureName");
                String fieldName = getOptionalString(request, "fieldName", null);
                Integer ordinal = getOptionalInteger(request.arguments(), "ordinal", null);
                String offsetString = getOptionalString(request, "offset", null);
                String dataTypeString = getString(request, "dataType");
                String archiveName = getOptionalString(request, "archiveName", null);
                String requestedFieldName = getOptionalString(request, "newFieldName", null);
                String requestedComment = request.arguments().containsKey("newComment")
                    ? getOptionalString(request, "newComment", null) : null;

                int selectors = 0;
                if (fieldName != null && !fieldName.isBlank()) selectors++;
                if (ordinal != null) selectors++;
                if (offsetString != null && !offsetString.isBlank()) selectors++;
                if (selectors != 1) {
                    return createErrorResult("Specify exactly one selector: fieldName, ordinal, or offset");
                }

                DataTypeManager dtm = program.getDataTypeManager();
                DataType dt = findDataTypeByName(dtm, structureName);
                if (!(dt instanceof Structure struct)) {
                    return createErrorResult("Data type is not a structure: " + structureName);
                }

                DataTypeComponent component = null;
                if (fieldName != null && !fieldName.isBlank()) {
                    for (DataTypeComponent comp : struct.getDefinedComponents()) {
                        if (fieldName.equals(comp.getFieldName())) {
                            component = comp;
                            break;
                        }
                    }
                    if (component == null) {
                        return createErrorResult("Component not found by fieldName: " + fieldName);
                    }
                }
                else if (ordinal != null) {
                    if (ordinal < 0 || ordinal >= struct.getNumComponents()) {
                        return createErrorResult("Ordinal out of range: " + ordinal);
                    }
                    component = struct.getComponent(ordinal);
                    if (component == null) {
                        return createErrorResult("Component not found at ordinal: " + ordinal);
                    }
                }
                else {
                    int offset;
                    try {
                        offset = Integer.decode(offsetString);
                    } catch (NumberFormatException e) {
                        return createErrorResult("Invalid offset: " + offsetString);
                    }
                    component = struct.getComponentAt(offset);
                    if (component == null) {
                        return createErrorResult("Component not found at offset: " + offsetString);
                    }
                }

                DataType newDataType;
                try {
                    newDataType = DataTypeParserUtil.parseDataTypeObjectFromString(dataTypeString, archiveName);
                } catch (Exception e) {
                    return createErrorResult("Failed to resolve datatype: " + e.getMessage());
                }
                if (newDataType == null) {
                    return createErrorResult("Failed to resolve datatype: " + dataTypeString);
                }

                newDataType = dtm.resolve(newDataType, DataTypeConflictHandler.DEFAULT_HANDLER);

                String oldFieldName = component.getFieldName();
                String oldComment = component.getComment();
                DataType oldDataType = component.getDataType();
                int componentOffset = component.getOffset();
                int oldLength = component.getLength();
                int originalStructLength = struct.getLength();
                int newLength = newDataType.getLength();
                if (newLength <= 0) {
                    return createErrorResult("New datatype must have a fixed positive size: " + dataTypeString);
                }
                if (newLength != oldLength) {
                    return createErrorResult("Datatype size mismatch for in-place replacement at offset 0x" +
                        Integer.toHexString(componentOffset) + ": old component length is " + oldLength +
                        " bytes but new datatype is " + newLength +
                        " bytes. This tool only supports fixed-size in-place replacement.");
                }

                String finalFieldName = requestedFieldName != null ? requestedFieldName : oldFieldName;
                String finalComment = request.arguments().containsKey("newComment") ? requestedComment : oldComment;

                List<Map<String, Object>> componentSpecs = new ArrayList<>();
                for (DataTypeComponent comp : struct.getDefinedComponents()) {
                    Map<String, Object> spec = new HashMap<>();
                    spec.put("offset", comp.getOffset());
                    spec.put("length", comp.getLength());
                    spec.put("fieldName", comp.getFieldName());
                    spec.put("comment", comp.getComment());
                    spec.put("dataType", comp.getDataType());
                    componentSpecs.add(spec);
                }
                for (Map<String, Object> spec : componentSpecs) {
                    if (((Integer) spec.get("offset")) == componentOffset) {
                        spec.put("dataType", newDataType);
                        spec.put("fieldName", finalFieldName);
                        spec.put("comment", finalComment);
                        spec.put("length", newLength);
                        break;
                    }
                }

                int txId = program.startTransaction("Set Structure Component Type");
                try {
                    struct.setPackingEnabled(false);
                    struct.deleteAll();
                    for (Map<String, Object> spec : componentSpecs) {
                        struct.insertAtOffset(
                            (Integer) spec.get("offset"),
                            (DataType) spec.get("dataType"),
                            (Integer) spec.get("length"),
                            (String) spec.get("fieldName"),
                            (String) spec.get("comment")
                        );
                    }
                    if (struct.getLength() < originalStructLength) {
                        struct.growStructure(originalStructLength - struct.getLength());
                    }
                    DataTypeComponent updated = struct.getComponentAt(componentOffset);

                    program.endTransaction(txId, true);

                    Map<String, Object> result = new HashMap<>();
                    result.put("message", "Successfully updated component datatype in structure: " + structureName);
                    result.put("structureName", struct.getName());

                    Map<String, Object> componentInfo = new HashMap<>();
                    componentInfo.put("ordinal", updated.getOrdinal());
                    componentInfo.put("offset", updated.getOffset());
                    componentInfo.put("length", updated.getLength());
                    componentInfo.put("oldLength", oldLength);
                    componentInfo.put("oldFieldName", oldFieldName);
                    componentInfo.put("newFieldName", updated.getFieldName());
                    componentInfo.put("oldDataType", oldDataType.getDisplayName());
                    componentInfo.put("newDataType", updated.getDataType().getDisplayName());
                    componentInfo.put("oldComment", oldComment);
                    componentInfo.put("newComment", updated.getComment());
                    result.put("component", componentInfo);
                    result.put("structure", createDetailedStructureInfo(struct));
                    return createJsonResult(result);
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to update structure component datatype", e);
                    return createErrorResult("Failed to update structure component datatype: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to delete a structure with reference checking
     */
    private void registerDeleteStructureTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("structureName", SchemaUtil.createStringProperty("Name of the structure to delete"));
        properties.put("force", SchemaUtil.createOptionalBooleanProperty("Force deletion even if structure is referenced (default: false)"));

        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("structureName");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("delete-structure")
            .title("Delete Structure")
            .description("Delete a structure from the program. " +
                         "Checks for references (function signatures, variables, memory) before deletion. " +
                         "Use force=true to delete anyway despite references.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String structureName = getString(request, "structureName");
                boolean force = getOptionalBoolean(request, "force", false);

                DataTypeManager dtm = program.getDataTypeManager();
                DataType dt = findDataTypeByName(dtm, structureName);

                if (dt == null) {
                    return createErrorResult("Structure not found: " + structureName);
                }

                // Check for references to this structure
                List<String> functionReferences = new ArrayList<>();
                List<String> memoryReferences = new ArrayList<>();

                // Check function parameters and return types
                ghidra.program.model.listing.FunctionIterator functions = program.getFunctionManager().getFunctions(true);
                while (functions.hasNext()) {
                    ghidra.program.model.listing.Function func = functions.next();

                    // Check return type
                    if (func.getReturnType().isEquivalent(dt)) {
                        functionReferences.add(func.getName() + " (return type)");
                    }

                    // Check parameters
                    for (ghidra.program.model.listing.Parameter param : func.getParameters()) {
                        if (param.getDataType().isEquivalent(dt)) {
                            functionReferences.add(func.getName() + " (parameter: " + param.getName() + ")");
                        }
                    }

                    // Check local variables
                    for (ghidra.program.model.listing.Variable var : func.getAllVariables()) {
                        if (var.getDataType().isEquivalent(dt)) {
                            functionReferences.add(func.getName() + " (variable: " + var.getName() + ")");
                        }
                    }
                }

                // Check memory for applied instances
                Listing listing = program.getListing();
                ghidra.program.model.listing.DataIterator dataIter = listing.getDefinedData(true);
                while (dataIter.hasNext()) {
                    Data data = dataIter.next();
                    if (data.getDataType().isEquivalent(dt)) {
                        memoryReferences.add(AddressUtil.formatAddress(data.getAddress()));
                    }
                }

                int totalReferences = functionReferences.size() + memoryReferences.size();

                // If references exist and not forcing, return warning
                if (totalReferences > 0 && !force) {
                    Map<String, Object> result = new HashMap<>();
                    result.put("canDelete", false);
                    result.put("deleted", false);

                    Map<String, Object> references = new HashMap<>();
                    references.put("count", totalReferences);
                    references.put("functions", functionReferences);
                    references.put("memoryLocations", memoryReferences);
                    result.put("references", references);

                    result.put("warning", "Structure '" + structureName + "' is referenced in " +
                               functionReferences.size() + " function(s) and " +
                               memoryReferences.size() + " memory location(s). " +
                               "Use force=true to delete anyway.");

                    return createJsonResult(result);
                }

                // Proceed with deletion
                int txId = program.startTransaction("Delete Structure");
                try {
                    boolean removed = dtm.remove(dt);

                    program.endTransaction(txId, true);

                    if (removed) {
                        Map<String, Object> result = new HashMap<>();
                        result.put("message", "Successfully deleted structure: " + structureName);
                        result.put("deleted", true);
                        result.put("hadReferences", totalReferences > 0);
                        result.put("referencesCleared", totalReferences);
                        return createJsonResult(result);
                    } else {
                        return createErrorResult("Failed to delete structure (may be locked or in use by another process)");
                    }

                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to delete structure", e);
                    return createErrorResult("Failed to delete structure: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Register tool to parse C header files
     */
    private void registerParseCHeaderTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.createStringProperty("Path of the program"));
        properties.put("headerContent", SchemaUtil.createStringProperty("C header file content"));
        properties.put("category", SchemaUtil.createOptionalStringProperty("Category path (default: /)"));

        List<String> required = new ArrayList<>();
        required.add("programPath");
        required.add("headerContent");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("parse-c-header")
            .title("Parse C Header")
            .description("Parse an entire C header file and create all structures")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get program and parameters using helper methods
                Program program = getProgramFromArgs(request);
                String headerContent = getString(request, "headerContent");
                String category = getOptionalString(request, "category", "/");

                DataTypeManager dtm = program.getDataTypeManager();
                CParser parser = new CParser(dtm);

                int txId = program.startTransaction("Parse C Header");
                List<Map<String, Object>> createdTypes = new ArrayList<>();

                try {
                    // Parse the entire header content as one unit to handle dependencies
                    CategoryPath catPath = new CategoryPath(category);
                    Category cat = dtm.createCategory(catPath);

                    // Use CParser to parse the entire header content
                    DataType dt = parser.parse(headerContent);
                    if (dt != null) {
                        DataType resolved = dtm.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                        if (cat != null && !resolved.getCategoryPath().equals(catPath)) {
                            cat.moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
                        }
                        createdTypes.add(createStructureInfo(resolved));
                    }

                    // If single parse didn't work, try parsing line by line
                    if (createdTypes.isEmpty()) {
                        String[] lines = headerContent.split("\n");
                        StringBuilder currentDef = new StringBuilder();

                        for (String line : lines) {
                            line = line.trim();
                            if (line.isEmpty()) continue;

                            currentDef.append(line).append("\n");

                            // If line ends with semicolon, try to parse this definition
                            if (line.endsWith(";")) {
                                try {
                                    DataType lineDt = parser.parse(currentDef.toString());
                                    if (lineDt != null) {
                                        DataType resolved = dtm.resolve(lineDt, DataTypeConflictHandler.REPLACE_HANDLER);
                                        if (cat != null && !resolved.getCategoryPath().equals(catPath)) {
                                            cat.moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
                                        }
                                        createdTypes.add(createStructureInfo(resolved));
                                    }
                                } catch (Exception e) {
                                    // Log but continue with other definitions
                                    Msg.warn(this, "Failed to parse definition: " + currentDef.toString().substring(0, Math.min(50, currentDef.length())) + "...");
                                }
                                currentDef = new StringBuilder(); // Reset for next definition
                            }
                        }
                    }

                    program.endTransaction(txId, true);

                    Map<String, Object> result = new HashMap<>();
                    result.put("message", "Successfully parsed header file");
                    result.put("createdCount", createdTypes.size());
                    result.put("createdTypes", createdTypes);
                    return createJsonResult(result);

                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.error(this, "Failed to parse header", e);
                    return createErrorResult("Failed to parse header: " + e.getMessage());
                }
            } catch (Exception e) {
                return createErrorResult("Error: " + e.getMessage());
            }
        });
    }

    /**
     * Helper method to find a data type by name in all categories
     */
    private DataType findDataTypeByName(DataTypeManager dtm, String name) {
        // First try direct lookup
        DataType dt = dtm.getDataType(name);
        if (dt != null) {
            return dt;
        }

        // Search all categories
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dataType = iter.next();
            if (dataType.getName().equals(name)) {
                return dataType;
            }
        }

        return null;
    }

    /**
     * Create basic structure info map
     */
    private Map<String, Object> createStructureInfo(DataType dt) {
        Map<String, Object> info = DataTypeParserUtil.createDataTypeInfo(dt);

        if (dt instanceof Composite) {
            Composite composite = (Composite) dt;
            info.put("isUnion", dt instanceof Union);
            info.put("numComponents", composite.getNumComponents());

            if (dt instanceof Structure) {
                Structure struct = (Structure) dt;
                info.put("isPacked", struct.isPackingEnabled());
                // hasFlexibleArray check would go here if method exists
            }
        }

        return info;
    }

    /**
     * Create detailed structure info including all fields
     */
    private Map<String, Object> createDetailedStructureInfo(Composite composite) {
        Map<String, Object> info = createStructureInfo(composite);

        // Add field information with undefined byte condensing
        List<Map<String, Object>> fields = new ArrayList<>();

        int i = 0;
        while (i < composite.getNumComponents()) {
            DataTypeComponent comp = composite.getComponent(i);

            // Check if this is an undefined byte that should be condensed
            if (isUndefinedField(comp)) {
                // Count consecutive undefined bytes
                int startOffset = comp.getOffset();
                int startOrdinal = comp.getOrdinal();
                int totalLength = 0;
                int count = 0;

                while (i < composite.getNumComponents()) {
                    DataTypeComponent nextComp = composite.getComponent(i);
                    if (!isUndefinedField(nextComp)) {
                        break;
                    }
                    totalLength += nextComp.getLength();
                    count++;
                    i++;
                }

                // Create a condensed entry for the undefined range
                Map<String, Object> fieldInfo = new HashMap<>();
                fieldInfo.put("ordinal", startOrdinal);
                fieldInfo.put("offset", startOffset);
                fieldInfo.put("length", totalLength);
                fieldInfo.put("fieldName", "<undefined>");
                fieldInfo.put("dataType", "undefined");
                fieldInfo.put("dataTypeSize", totalLength);
                fieldInfo.put("isBitfield", false);
                fieldInfo.put("isCondensed", true);
                fieldInfo.put("componentCount", count);

                fields.add(fieldInfo);
            } else {
                // Regular field - add as-is
                Map<String, Object> fieldInfo = new HashMap<>();

                fieldInfo.put("ordinal", comp.getOrdinal());
                fieldInfo.put("offset", comp.getOffset());
                fieldInfo.put("length", comp.getLength());
                fieldInfo.put("fieldName", comp.getFieldName());
                fieldInfo.put("comment", comp.getComment());

                DataType fieldType = comp.getDataType();
                fieldInfo.put("dataType", fieldType.getDisplayName());
                fieldInfo.put("dataTypeSize", fieldType.getLength());

                // Check if it's a bitfield
                if (comp.isBitFieldComponent()) {
                    BitFieldDataType bitfield = (BitFieldDataType) fieldType;
                    fieldInfo.put("isBitfield", true);
                    fieldInfo.put("bitSize", bitfield.getBitSize());
                    fieldInfo.put("bitOffset", bitfield.getBitOffset());
                    fieldInfo.put("baseDataType", bitfield.getBaseDataType().getDisplayName());
                } else {
                    fieldInfo.put("isBitfield", false);
                }

                fieldInfo.put("isCondensed", false);

                fields.add(fieldInfo);
                i++;
            }
        }

        info.put("fields", fields);

        // Add C representation for both structures and unions
        info.put("cRepresentation", generateCRepresentation(composite));

        return info;
    }

    /**
     * Check if a field is an undefined/default field that should be condensed.
     * Requires BOTH a default/missing name AND an undefined datatype to avoid
     * false positives on user-named fields or user-created types.
     */
    private boolean isUndefinedField(DataTypeComponent comp) {
        // Check if the datatype is actually undefined
        if (!Undefined.isUndefined(comp.getDataType())) {
            return false;
        }

        // Also require a default or missing field name
        String fieldName = comp.getFieldName();
        if (fieldName == null || fieldName.isEmpty()) {
            return true;
        }

        // Ghidra default field names for undefined areas
        if (fieldName.startsWith("field_0x") || fieldName.startsWith("field0x")) {
            return true;
        }

        return false;
    }

    /**
     * Generate C representation of a composite type (structure or union) with undefined byte condensing
     */
    private String generateCRepresentation(Composite composite) {
        StringBuilder sb = new StringBuilder();
        String keyword = (composite instanceof Union) ? "union" : "struct";
        sb.append(keyword).append(" ").append(composite.getName()).append(" {\n");

        int i = 0;
        while (i < composite.getNumComponents()) {
            DataTypeComponent comp = composite.getComponent(i);
            sb.append("    ");

            // Check if this is an undefined field that should be condensed
            // (only applicable to structures, unions don't have undefined padding)
            if (composite instanceof Structure && isUndefinedField(comp)) {
                // Count consecutive undefined bytes
                int startOffset = comp.getOffset();
                int totalLength = 0;
                int count = 0;

                while (i < composite.getNumComponents()) {
                    DataTypeComponent nextComp = composite.getComponent(i);
                    if (!isUndefinedField(nextComp)) {
                        break;
                    }
                    totalLength += nextComp.getLength();
                    count++;
                    i++;
                }

                // Generate condensed line using valid C type for round-trip compatibility
                sb.append("uint8_t reserved_0x");
                sb.append(String.format("%x", startOffset));
                sb.append("[").append(totalLength).append("]");
                sb.append(";");
                sb.append(" // undefined padding 0x");
                sb.append(String.format("%x", startOffset));
                sb.append("-0x");
                sb.append(String.format("%x", startOffset + totalLength - 1));
                sb.append("\n");
            } else {
                // Regular field - output as-is
                DataType fieldType = comp.getDataType();
                if (comp.isBitFieldComponent()) {
                    BitFieldDataType bitfield = (BitFieldDataType) fieldType;
                    sb.append(bitfield.getBaseDataType().getDisplayName());
                    sb.append(" ").append(comp.getFieldName());
                    sb.append(" : ").append(bitfield.getBitSize());
                } else {
                    sb.append(fieldType.getDisplayName());
                    sb.append(" ").append(comp.getFieldName());
                }

                sb.append(";");

                if (comp.getComment() != null) {
                    sb.append(" // ").append(comp.getComment());
                }

                sb.append("\n");
                i++;
            }
        }

        sb.append("};");
        return sb.toString();
    }

}