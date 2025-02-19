#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
解析自定义协议报文的脚本示例

用法:
    python parse_protocol.py <hex_string>

示例:
    python parse_protocol.py "6800AB6823350010000000110631610680000100000001124000010000050A128000010000001E13010001000001F42720000400000001130200010000001E130400010000010E13080001000007D02740000400000001131000010000010E13200001000001C21340000100000320278000040000000113800001000001E0140100010000050A14020001FFFFFE0C2801000400000001270800010000000027100004000000000F0100040000001D323F16"
"""

import sys
import binascii

def parse_hex_string(hex_str):
    """
    将输入的十六进制字符串（无空格或带空格均可）转换为 bytes 对象。
    """
    # 移除所有空白字符，并转换为小写
    clean_str = "".join(hex_str.split()).lower().replace("0x", "")
    try:
        return binascii.unhexlify(clean_str)
    except Exception as e:
        print("输入的十六进制数据格式错误:", e)
        sys.exit(1)
def parse_da_table_number(da_bytes):
    da_h = da_bytes[0]
    da_l = da_bytes[1]

    base_number = (da_h - 1) * 8 + 1

    # 计算低位对应的具体表号，并累加
    total_table_number = 0
    for i in range(8):
        if da_l & (1 << i):
            total_table_number += (base_number + i)

    return total_table_number

def parse_frame(frame_bytes):
    """
    根据协议解析单个帧，返回一个字典包含各字段解析结果：
      {
        'start_flag': int,
        'length': int,
        'start_flag2': int,
        'address': bytes,
        'afn': int,
        'dir': int,
        'seq': bytes,
        'data_units': [ { 'DA': hex, 'DT': hex, 'value': int, 'result_code': int or None }, ... ],
        'crc': int,
        'end_flag': int
      }
    """
    parsed = {}
    offset = 0

    # 1. 起始字符(1字节)
    parsed['start_flag'] = frame_bytes[offset]
    offset += 1

    # 2. 长度 L (2字节)
    length_bytes = frame_bytes[offset:offset+2]
    parsed['length'] = int.from_bytes(length_bytes, byteorder='big')
    offset += 2

    # 3. 第二个起始字符(1字节)
    parsed['start_flag2'] = frame_bytes[offset]
    offset += 1

    # 4. 地址域 A (8字节)
    parsed['address'] = frame_bytes[offset:offset+8]
    offset += 8

    # 5. 应用层数据：AFN (1字节) + SEQ (2字节)
    parsed['afn'] = frame_bytes[offset]
    offset += 1

    # 根据 AFN 最高位判断方向（示例中采用 D7 表示 DIR）
    parsed['dir'] = (parsed['afn'] & 0x80) >> 7
    parsed['seq'] = frame_bytes[offset:offset+2]
    offset += 2

    # 6. 解析数据单元：
    # 下行（DIR=0）: 每个数据单元 = 4 字节标识 + 4 字节数据 = 8 字节
    # 上行（DIR=1）: 每个数据单元 = 4 字节标识 + 4 字节数据 + 1 字节结果码 = 9 字节
    dt_mapping = {
        1: ('F1', 4),
        2: ('F2', 'var'),
        8: ('F4', 8),  # 根据样例，DT==0004的数据为4字节，视作枚举类型F3
        4: ('F3', 4),
    }

    data_units = []
    while (len(frame_bytes) - offset) > 3:  # 保证剩余字节足够CRC+结束符
        if (len(frame_bytes) - offset) < 4:
            break

        da_dt = frame_bytes[offset:offset + 4]
        offset += 4
        da_val = da_dt[:2]
        da_table_number = parse_da_table_number(da_val)
        dt_val = da_dt[2:]

        dt_int = int.from_bytes(dt_val, byteorder='big')

        # 根据DT值决定数据类型和长度
        data_type, fixed_length = dt_mapping.get(dt_int, ('F1', 4))

        # 打印解析到的数据类型和长度
        print(f"解析数据单元：DA={da_val.hex().upper()} DT={dt_val.hex().upper()} 类型={data_type} 长度={fixed_length if fixed_length else '不定长'}")

        # 按数据类型读取数据值
        if data_type == 'F2':  # F2类型（ASCII），长度由接下来的2个字节决定
            if (len(frame_bytes) - offset) < 2:
                break
            length_bytes = frame_bytes[offset:offset + 2]
            ascii_length = int.from_bytes(length_bytes, byteorder='big')
            offset += 2

            if (len(frame_bytes) - offset) < ascii_length:
                break
            data_val = frame_bytes[offset:offset + ascii_length]
            offset += ascii_length
            data_result = data_val.decode('ascii', errors='ignore')

        elif fixed_length:  # 其他固定长度类型
            if (len(frame_bytes) - offset) < fixed_length:
                break
            data_val = frame_bytes[offset:offset + fixed_length]
            offset += fixed_length

            if data_type in ('F1', 'F3'):
                data_result = int.from_bytes(data_val, byteorder='big', signed=True)
            elif data_type == 'F4':
                data_result = int.from_bytes(data_val, byteorder='big', signed=False)
            elif data_type == 'F5':
                data_result = data_val.hex().upper()

        else:
            break

        # 处理上行帧结果码
        result_code = None
        if parsed['dir'] == 1 and parsed['afn'] == 6:
            if (len(frame_bytes) - offset) < 1:
                break
            result_code = frame_bytes[offset]
            offset += 1

        data_units.append({
            'DA': da_val.hex().upper(),
            'DA_table_number': da_table_number,  # 表号，比如4、9、19
            'DT': dt_val.hex().upper(),
            'value': data_result,
            'result_code': result_code,
            'data_type': data_type,
            'length': ascii_length if data_type == 'F2' else fixed_length
        })


    parsed['data_units'] = data_units

    # 7. CRC (2字节)
    if (len(frame_bytes) - offset) >= 2:
        parsed['crc'] = int.from_bytes(frame_bytes[offset:offset+2], byteorder='big')
        offset += 2
    else:
        parsed['crc'] = None

    # 8. 结束字符 (1字节)
    if (len(frame_bytes) - offset) >= 1:
        parsed['end_flag'] = frame_bytes[offset]
        offset += 1
    else:
        parsed['end_flag'] = None

    return parsed

def print_parsed(parsed):
    """
    打印解析结果
    """
    print("========== 解析结果 ==========")
    print(f"起始字符: 0x{parsed['start_flag']:02X}")
    print(f"长度 L: {parsed['length']} (十进制)")
    print(f"第二个起始字符: 0x{parsed['start_flag2']:02X}")
    print(f"地址域 A: {parsed['address'].hex().upper()}")
    print(f"AFN: 0x{parsed['afn']:02X}")
    print(f"方向 DIR: {parsed['dir']} (0=下行, 1=上行)")
    print(f"SEQ: {parsed['seq'].hex().upper()}")

    print("\n--- 数据单元列表 ---")
    for idx, unit in enumerate(parsed['data_units'], start=1):
        line = f"[单元{idx}] DA={unit['DA']} (点数： {unit['DA_table_number']}) DT={unit['DT']} "

        # 根据数据类型来决定如何显示 Value
        if unit.get('data_type') == 'F2':
            # ASCII 字符串数据
            line += f"Value=\"{unit['value']}\""
        elif unit.get('data_type') == 'F5':
            # F5 以十六进制显示
            line += f"Value=0x{unit['value']:X}"
        else:
            # F1, F3 等按整数显示
            line += f"Value={unit['value']}"

        if unit['result_code'] is not None:
            line += f" ResultCode=0x{unit['result_code']:02X}"

        print(line)


    if parsed['crc'] is not None:
        print(f"\nCRC: 0x{parsed['crc']:04X}")
    else:
        print("CRC: None")
    if parsed.get('end_flag') is not None:
        print(f"结束字符: 0x{parsed['end_flag']:02X}")
    else:
        print("结束字符: None")
    print("==============================\n")

def parse_da_table_number(da_bytes):
    da_h = da_bytes[0]
    da_l = da_bytes[1]

    base_number = (da_h - 1) * 8 + 1

    # 计算低位对应的具体表号，并累加
    total_table_number = 0
    for i in range(8):
        if da_l & (1 << i):
            total_table_number += (base_number + i)

    return total_table_number

def main():
    if len(sys.argv) < 2:
        print("用法: python parse_protocol.py <hex_string>")
        print("示例: python parse_protocol.py \"6800AB6823350010000000110631610680000100000001124000010000050A128000010000001E13010001000001F42720000400000001130200010000001E130400010000010E13080001000007D02740000400000001131000010000010E13200001000001C21340000100000320278000040000000113800001000001E0140100010000050A14020001FFFFFE0C2801000400000001270800010000000027100004000000000F0100040000001D323F16\"")
        sys.exit(1)

    hex_input = sys.argv[1]
    frame = parse_hex_string(hex_input)
    parsed = parse_frame(frame)
    print_parsed(parsed)

if __name__ == "__main__":
    main()
