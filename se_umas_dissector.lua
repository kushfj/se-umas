-- References:
--   * https://wiki.wireshark.org/Lua/Dissectors
--   * 



-- declare global parameters
--- WARNING: these names have to be unique, so if you have other plugins which have dissectors with the name protocol name you need to change these to make them unique
local protocol_modbus = Proto("mbus_umas", "Modbus (UMAS)")
local protocol_se_umas = Proto("modbus.umas", "SE UMAS")

-- define fields for modbus protocol
local field_mbus_trans_id = ProtoField.uint16("modbus.trans_id", "Transaction ID", base.DEC)
local field_mbus_proto_id = ProtoField.uint16("modbus.proto_id", "Protocol ID", base.DEC)
local field_mbus_length = ProtoField.uint16("modbus.length", "Length", base.DEC)
local field_mbus_unit_id = ProtoField.uint8("modbus.unit_id", "Unit ID", base.DEC)
local field_mbus_func_code = ProtoField.uint8("modbus.func_code", "Function Code", base.DEC)
protocol_modbus.fields = { field_mbus_trans_id, field_mbus_proto_id, field_mbus_length, field_mbus_unit_id, field_mbus_func_code }

-- define fields for UMAS protocol
local field_umas_session_id = ProtoField.uint8("se_umas.session_id", "Session ID", base.HEX)
local field_umas_func_code = ProtoField.uint8("se_umas.func_code", "Function Code", base.DEC)
local field_umas_data = ProtoField.string("se_umas.data", "Data", base.ASCII)
protocol_se_umas.fields = { field_umas_session_id, field_umas_func_code, field_umas_data }



-- https://hitcon.org/2021/agenda/b128a44d-c492-410f-b04c-045548ce0590/Debacle%20of%20The%20Maginot%20Line%EF%BC%9AGoing%20Deeper%20into%20Schneider%20Modicon%20PAC%20Security.pdf
-- map decimal SE UMAS function code to a descriptive name for the code
local map_se_umas_func_code_to_name = {
    [1] = "0x01: Get comm info",
    [2] = "0x02: Get PLC info",
    [3] = "0x03: GAI object info",
    [4] = "0x04: Get PLC status",
    [5] = "0x05: Get loader info",
    [6] = "0x06: Get memory card info",
    [7] = "0x07: Get block info",
    [10] = "0x0a: Mirror",
    [16] = "0x10: Take PLC reservation",
    [17] = "0x11: Release PLC reservation",
    [18] = "0x12: Keep PLC reservation",
    [32] = "0x20: Read memory block",
    [33] = "0x21: Write memory block",
    [34] = "0x22: Read BOL",
    [35] = "0x23: Write BOL",
    [36] = "0x24: Read var list",
    [37] = "0x25: Write var list",
    [38] = "0x26: Data dictionary",
    [39] = "0x27: Data dictionary preload",
    [40] = "0x28: Read phy. address",
    [41] = "0x29: Write phy. address",
    [42] = "0x2a: Browse events",
    [48] = "0x30: Begin download",
    [49] = "0x31: Download packet",
    [50] = "0x32: End download",
    [51] = "0x33: Begin upload",
    [52] = "0x34: Upload packet",
    [53] = "0x35: End upload",
    [54] = "0x36: Do backup/restore backup/compare backup/clear backup",
    [55] = "0x37: Pre-load blocks",
    [64] = "0x40: Start task",
    [65] = "0x41: Stop task",
    [66] = "0x42: Init. PLC",
    [67] = "0x43: Swap",
    [80] = "0x50: Req. analyse",
    [81] = "0x51: Get auto modif",
    [82] = "0x52: Get forced bits",
    [83] = "0x53: Get selected blocks",
    [88] = "0x58: Query diag.",
    [96] = "0x60: Breakpoint set",
    [97] = "0x61: Breakpoint reset/delete",
    [98] = "0x62: Step over",
    [99] = "0x63: Step in",
    [100] = "0x64: Step out",
    [101] = "0x65: Get call stack",
    [102] = "0x66: Check debug allowed",
    [108] = "0x6c: Process msg.",
    [109] = "0x6d: Private msg.",
    [110] = "0x6e: Enhanced resv. mngt.",
    [112] = "0x70: Request read IO obj.",
    [113] = "0x71: Request write IO obj.",
    [114] = "0x72: Read rack",
    [115] = "0x73: Read module",
    [116] = "0x74: Read device data",
    [253] = "0xfd: Response (error)",
    [254] = "0xfe: Response (success)"
}



-- create a function to get the SE UMAS function name for a given SE UMAS function code
-- @param se_umas_func_code - the SE UMAS function code
-- @return string - name name of the SE UMAS functin code or "Function code unknown" if the function code is not found in the mapping
local function get_se_umas_function_name(se_umas_func_code)
	-- attempt to get the mapped name 
	local name = map_se_umas_func_code_to_name[se_umas_func_code] 

	-- check if we got a valid name
	if name ~= nil then 
		return name 
	else 
		return "Function code unknown"
	end
end



-- create a function to dissect protocol from buffer and update the packet information and protocol tree
-- @param buffer - the reference to the buffer of bytes containing the frame data
-- @param pinfo - the reference to the Wireshark packet information list to be updated
-- @param tree - the reference to the Wireshark protocol tree to be updated with the dissected fields
function protocol_se_umas.dissector(buffer, pinfo, tree)

	-- declare local variables
	local modbus_dissector = Dissector.get("mbtcp") -- original modbus TCP dissector
	local buffer_length = buffer:len() -- length of the buffer 10-4096, typically 1480
	local modbus_func_code = buffer(7,1):uint() -- modbus function code, should be 0x5a (90) for UMAS

	-- check that it is in-fact SE UMAS based on modbus FC 0x5a (90)
	if modbus_func_code ~= 90 then
		modbus_dissector:call(buffer, pinfo, tree) -- call the original modbus TCP dissector
		return
	end

	-- check if it's not a valid SE UMAS packet
	if (buffer_length < 10) or (buffer_length > 4096) then
		modbus_dissector:call(buffer, pinfo, tree) -- call the original modbus TCP dissector
		return
	end

	-- extract modbus fields from buffer and set field values into sub-tree
	local tree_modbus = tree:add(protocol_modbus, buffer(), "Modbus")
	tree_modbus:add(field_mbus_trans_id, buffer(0, 2))
	tree_modbus:add(field_mbus_proto_id, buffer(2, 2))
	tree_modbus:add(field_mbus_length, buffer(4, 2))
	tree_modbus:add(field_mbus_unit_id, buffer(6, 1))
	tree_modbus:add(field_mbus_func_code, modbus_func_code):append_text(" (SE UMAS)") -- append text description to modbus function code to indicate SE UMAS/Unity protocol use

	-- extract UMAS fields from buffer and set field values into sub-tree
	local se_umas_func_code = buffer(9,1) -- get the 1-byte UMAS function code at offset 9
	local se_umas_func_name = get_se_umas_function_name(se_umas_func_code:uint())
	local se_umas_data = buffer(10):bytes():tohex()

	local tree_se_umas = tree_modbus:add(protocol_se_umas, buffer(8), "UMAS")
	tree_se_umas:add(field_umas_session_id, buffer(8,1))
	tree_se_umas:add(field_umas_func_code, se_umas_func_code):append_text(" (".. se_umas_func_name ..")") -- append UMAS function name to the UMAS function code
	-- TODO - fix this to extract data based on function code
	tree_se_umas:add(field_umas_data, se_umas_data)

	-- set protocol in packet information (pinfo) list
	pinfo.cols.protocol = "Modbus UMAS" 
	pinfo.cols.info = se_umas_func_name
end



-- load the tcp.port dissector table and register the protocol dissector to handle tcp port 502
local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(502, protocol_se_umas)
