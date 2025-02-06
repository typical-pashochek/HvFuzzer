import idaapi
import idautils
import idc
import ida_hexrays
import re
import json


def get_max_offset(code_line):
    pattern = re.compile(r"a1 \+ (\d+)")
    matches = pattern.findall(code_line)
    offsets = list(map(int, matches))
    return max(offsets) if offsets else None


def find_switch_in_function(func_ea):
    switch_cases = []

    for head in idautils.Heads(func_ea, idc.get_func_attr(func_ea, idc.FUNCATTR_END)):
        if idaapi.is_code(idaapi.get_full_flags(head)):
            si = idaapi.get_switch_info(head)
            if si:
                return head, si
    return 0, 0


def get_cases(switch_info):
    cases = []
    jump_table_address = switch_info.jumps
    element_size = switch_info.get_jtable_element_size()
    ncases = switch_info.ncases

    print(f"[+] Jump table: {hex(jump_table_address)}")
    print(f"[+] Element size: {element_size} bytes")
    print(f"[+] Number of cases: {ncases}")
    
    for i in range(ncases):
        if element_size == 4:
            ea = idc.get_wide_dword(jump_table_address + i * element_size) 
        else:
            ea = idc.get_qword(jump_table_address + i * element_size)
        
        ea += 0x140000000
        # print(f"[+] Case {i} address: {hex(ea)}")
        if ea != idaapi.BADADDR:
            cases.append(ea)

    return cases


def get_case_bounds(case_address):
    func = idaapi.get_func(case_address)
    if not func:
        print(f"[!] Can't find function for address {hex(case_address)}")
        return None
    
    for head in idautils.Heads(case_address, func.end_ea):
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, head):
            if insn.get_canon_mnem() == "jmp":
                return case_address, head
            
    return None


def get_block(start_addr, end_addr):
    if not ida_hexrays.init_hexrays_plugin():
        print("[!] Hex-Rays Decompiler not initialized.")
        exit()
    
    cfunc = idaapi.decompile(start_addr)
    
    if not cfunc:
        print(f"[!] Can't decompile in address {hex(func.start_ea)}")
        exit()
    
    block = ""
    
    for cf in cfunc.treeitems:
            if cf.op == idaapi.cot_call:
                if start_addr <= cf.ea <= end_addr:
                    decompiled_call_string = cf.cexpr.dstr()
                    # print(f"\t{decompiled_call_string}")
                    block += decompiled_call_string
    
    return block


def process_switch_cases(si):
    
    case_targets = get_cases(si)

    if not case_targets:
        print("[!] Can't get case values table.")
        return
    
    secure_services = {}
    for case_value, case_addr in enumerate(case_targets):
        # print(f"Case {case_value + 1}:")
        
        bounds = get_case_bounds(case_addr)
        if not bounds:
            continue

        block_start, block_end = bounds
        # print(f"block_start: {hex(block_start)}, block_end: {hex(block_end)}")

        block = get_block(block_start, block_end)
        
        secure_services[case_value + 1] = get_max_offset(block) + 8
    
    with open("secure_services.txt", 'w') as file:
        json.dump(secure_services, file)
                

def main():
    function_name = "IumInvokeSecureService"
    func_ea = idc.get_name_ea_simple(function_name)

    if func_ea == idc.BADADDR:
        print(f"[!] Function {function_name} not found.")
        return
    
    print(f"[+] {function_name} : {hex(func_ea)}")
    
    switch_ea, switch_info = find_switch_in_function(func_ea)
    
    if not switch_ea:
        print("[!] No switch-case.")
        return
        
    print(f"[+] switch-case: {hex(switch_ea)}")
    
    process_switch_cases(switch_info)


if __name__ == "__main__":
    main()
