#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
l0ck3d_recovery.py — C3RB3R/.L0CK3D 勒索软件数据抢救工具
==========================================================

针对基于 Conti v3 泄露源码的 C3RB3R 勒索软件（.L0CK3D / .LOCK3D 扩展名，
曾通过 CVE-2023-22518 等漏洞攻击群晖等 NAS 设备）的加密文件，
在**不接触任何攻击者基础设施、不支付赎金**的前提下，
从幸存数据中尽可能抢救回可播放/可查看的内容。

工作原理（逆向自真实样本 + Conti v3 泄露源码）：
  加密文件容器 = [数据区 f4 字节][304B 密钥材料][264B 零][20B 尾注]
  尾注 = [magic 4B][模式 1B][百分比 1B][u16][u32 f3][u32 原始大小 f4][u32 0]
  模式：0x24 FULL   —— 原始文件 <=1MB   ：整体加密，无法恢复
        0x26 HEADER —— 原始文件 1~5MB ：仅加密前 1MB，其余为明文
        0x25 PARTLY —— 原始文件 >5MB  ：按百分比分 3 段加密（约 12%），
                       PartSize=(原始大小//100)*4，三段均匀分布，末段必达文件尾
  即：大文件的约 88% 数据以明文幸存，按格式重建即可抢救。

支持的抢救类型：
  FLAC   —— 从明文区提取全部帧切片，重建文件头，输出可播放 FLAC（实测 ~88%）
  MP3    —— 定位第一个完整帧同步，切除加密头部，输出可播放 MP3
  WAV    —— 在明文区重写 RIFF 头（尝试常见采样率组合）
  JPG    —— 雕刻明文区里的嵌入预览图（三星等相机普遍内嵌 640x480 预览）
  MP4/HEVC —— 提取明文区全部 NAL 帧切片为 .h265/.264 素材流（装配需参数集）
  其他   —— 分诊报告（明文区结构扫描）

用法：
  python l0ck3d_recovery.py <文件或文件夹> [-o 输出目录] [--report 报告.md]

仅使用 Python 标准库；JPG 校验如安装了 Pillow 会更严格（可选）。
原始加密文件永远只读，不会被修改。

免责声明：本工具仅用于受害者对自己数据的合法自救。
"""

import argparse
import collections
import math
import os
import struct
import sys
import time
import traceback

# ----------------------------------------------------------------------
# 容器解析
# ----------------------------------------------------------------------

TRAILER = 588          # [数据区][304B 密钥材料][264B 零][20B 尾注]
FOOTER = 20

MODE_NAME = {0x24: "FULL(整体加密)", 0x25: "PARTLY(分段加密)", 0x26: "HEADER(头部加密)"}


def parse_container(d):
    """识别 .L0CK3D 容器结构，返回描述 dict；不像本家族则返回 None"""
    n = len(d)
    if n < TRAILER + 64:
        return None
    mode = d[n - 16]
    if mode not in MODE_NAME:
        return None
    percent = d[n - 15]
    f4 = int.from_bytes(d[n - 8:n - 4], "little")
    f3 = int.from_bytes(d[n - 12:n - 8], "little")
    data_end = n - TRAILER
    ok = (f4 == data_end - 304) or (f4 == data_end)
    return dict(size=n, mode=mode, mode_name=MODE_NAME[mode], percent=percent,
                f2=int.from_bytes(d[n - 16 - 4:n - 16], "little") if False else None,
                f4=f4, f3=f3, data_end=data_end, data_start=0,
                orig_size=f4, footer_ok=ok)


def encrypted_chunks(data_end, orig_size, percent):
    """按泄露源码算法计算加密区位置（PARTLY 模式），返回 [(start,end), ...]"""
    PartSize = (orig_size // 100) * 4
    if PartSize <= 0:
        return [(0, orig_size)]
    if orig_size <= 5 * 1048576:
        return [(0, min(1048576, orig_size))]          # HEADER 模式
    chunks = [(0, PartSize)]
    gap_total = orig_size - 3 * PartSize
    if gap_total < 0:
        return [(0, orig_size)]
    g1 = gap_total // 2
    c2s = PartSize + g1
    chunks.append((c2s, c2s + PartSize))
    chunks.append((orig_size - PartSize, orig_size))
    return chunks


def in_chunks(p, chunks):
    for a, b in chunks:
        if a <= p < b:
            return True
    return False


def plaintext_spans(n_data, chunks):
    """数据区里所有明文区段 [(start,end), ...]"""
    spans = []
    cur = 0
    for a, b in sorted(chunks):
        if a > cur:
            spans.append((cur, min(a, n_data)))
        cur = max(cur, b)
    if cur < n_data:
        spans.append((cur, n_data))
    return [(a, b) for a, b in spans if b > a]


# ----------------------------------------------------------------------
# CRC / 位工具
# ----------------------------------------------------------------------

def crc8(buf):
    crc = 0
    for b in buf:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


_CRC16_TAB = []
for _i in range(256):
    _c = _i << 8
    for _ in range(8):
        _c = ((_c << 1) ^ 0x8005) & 0xFFFF if _c & 0x8000 else (_c << 1) & 0xFFFF
    _CRC16_TAB.append(_c)


def crc16(buf):
    crc = 0
    for b in buf:
        crc = ((crc << 8) & 0xFFFF) ^ _CRC16_TAB[((crc >> 8) ^ b) & 0xFF]
    return crc


# ----------------------------------------------------------------------
# FLAC：帧提取 + 头部重建
# ----------------------------------------------------------------------

_HEVC_BS_TYPES = {0: "B", 1: "P", 2: "I"}
_FLAC_BS = {0: None, 1: 192, 2: 576, 3: 1152, 4: 2304, 5: 4608, 8: 256, 9: 512,
            10: 1024, 11: 2048, 12: 4096, 13: 8192, 14: 16384, 15: 32768}
_FLAC_SR = {0: None, 1: 88200, 2: 176400, 3: 192000, 4: 8000, 5: 16000, 6: 22050,
            7: 24000, 8: 32000, 9: 44100, 10: 48000, 11: 96000}


def flac_ue(buf, i):
    b = buf[i]
    ones = 0
    while ones < 8 and b & (0x80 >> ones):
        ones += 1
    if ones == 1 or ones > 7:
        return None, 0
    if ones == 0:
        return b & 0x7F, 1
    val = b & (0xFF >> (ones + 1))
    for j in range(1, ones):
        if i + j >= len(buf) or buf[i + j] & 0xC0 != 0x80:
            return None, 0
        val = (val << 6) | (buf[i + j] & 0x3F)
    return val, ones


def flac_parse_frame(buf, i):
    n = len(buf)
    if i + 7 > n:
        return None
    if buf[i] != 0xFF or buf[i + 1] & 0xFE != 0xF8 or buf[i + 1] & 0x02:
        return None
    if buf[i + 3] & 0x01:
        return None
    bs_code = buf[i + 2] >> 4
    sr_code = buf[i + 2] & 0x0F
    ch_code = buf[i + 3] >> 4
    depth_code = (buf[i + 3] >> 1) & 0x07
    pos = i + 4
    num, consumed = flac_ue(buf, pos)
    if num is None:
        return None
    pos += consumed
    if bs_code == 6:
        bsize = buf[pos] + 1; pos += 1
    elif bs_code == 7:
        if pos + 1 >= n:
            return None
        bsize = struct.unpack_from(">H", buf, pos)[0] + 1; pos += 2
    else:
        bsize = _FLAC_BS.get(bs_code)
        if bsize is None:
            return None
    if sr_code == 12:
        srate = buf[pos] * 1000; pos += 1
    elif sr_code in (13, 14):
        if pos + 1 >= n:
            return None
        srate = struct.unpack_from(">H", buf, pos)[0]
        if sr_code == 14:
            srate *= 10
        pos += 2
    else:
        srate = _FLAC_SR.get(sr_code)
        if srate is None:
            return None
    if pos >= n or crc8(buf[i:pos]) != buf[pos]:
        return None
    return dict(off=i, hlen=pos + 1 - i, bsize=bsize, srate=srate,
                ch=ch_code, depth=depth_code, num=num)


def recover_flac(data, spans, out_path, log):
    """从明文区提取 FLAC 帧并重建可播放文件，返回 (输出路径, 统计) 或 None"""
    n = len(data)
    frames = []
    for a, b in spans:
        i = a
        while i < min(b, n) - 8:
            j = data.find(b"\xff", i, b)
            if j < 0 or j + 1 >= n:
                break
            if j + 1 < n and data[j + 1] & 0xFE == 0xF8 and not data[j + 1] & 0x02 \
                    and not data[j + 3] & 0x01:
                fr = flac_parse_frame(data, j)
                if fr:
                    frames.append(fr)
            i = j + 1
    if not frames:
        return None
    # 串成链（帧号连续），剔除假阳性
    runs = [[frames[0]]]
    for fr in frames[1:]:
        if fr["num"] == runs[-1][-1]["num"] + 1:
            runs[-1].append(fr)
        elif fr["num"] == runs[-1][-1]["num"]:
            continue
        else:
            runs.append([fr])
    runs = [r for r in runs if len(r) > 10]
    if not runs:
        return None
    bsize = runs[0][0]["bsize"]
    srate = runs[0][0]["srate"]
    spans_out = []
    for ri, r in enumerate(runs):
        for k in range(len(r) - 1):
            spans_out.append((r[k], r[k + 1]["off"]))
        if ri + 1 < len(runs):
            nxt = runs[ri + 1][0]["off"]
            if crc16_ok(data, r[-1]["off"], nxt):
                spans_out.append((r[-1], nxt))
            else:
                log("    边界帧(原#%d)结束位置无法验证，舍弃" % r[-1]["num"])
    spans_out.append((runs[-1][-1], n))   # 最后一帧延伸到数据区末尾，稍后裁剪
    # 最后一帧的结束 = 明文区末尾；它的 CRC 无法核验，舍弃
    spans_out.pop()
    if not spans_out:
        return None
    # 重建
    out = bytearray(b"fLaC")
    out += struct.pack(">I", (1 << 31) | 34)
    total_est = len(spans_out) * bsize
    si = struct.pack(">HH", bsize, bsize) + b"\x00" * 6
    si += struct.pack(">Q", (srate << 44) | (1 << 41) | (15 << 36) | total_est)
    si += b"\x00" * 16
    out += si

    def utf8_enc(v):
        if v < 0x80:
            return bytes([v])
        if v < 0x800:
            return bytes([0xC0 | (v >> 6), 0x80 | (v & 0x3F)])
        return bytes([0xE0 | (v >> 12), 0x80 | ((v >> 6) & 0x3F), 0x80 | (v & 0x3F)])

    o = 4 + 4 + 34
    for idx, (fr, end) in enumerate(spans_out):
        body = data[fr["off"] + fr["hlen"]:end - 2]
        hdr = b"\xff\xf8" + bytes([0xC9, (fr["ch"] << 4) | (fr["depth"] << 1)]) + utf8_enc(idx)
        hdr += bytes([crc8(hdr)])
        frame = hdr + body
        frame += struct.pack(">H", crc16(frame))
        out += frame
    with open(out_path, "wb") as fh:
        fh.write(out)
    dur = len(spans_out) * bsize / srate
    stats = dict(frames=len(spans_out), size=len(out), duration=dur, srate=srate)
    return out_path, stats


def crc16_ok(data, start, end):
    if end - 2 <= start:
        return False
    stored = struct.unpack_from(">H", data, end - 2)[0]
    return stored == crc16(data[start:end - 2])


# ----------------------------------------------------------------------
# MP3：帧同步定位 + 切头
# ----------------------------------------------------------------------

_MP3_BR_V1L3 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
_MP3_BR_V2L3 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0]
_MP3_SR = {3: 44100, 2: 22050, 0: 11025}


def mp3_frame_len(buf, i):
    if i + 4 > len(buf) or buf[i] != 0xFF or (buf[i + 1] & 0xE0) != 0xE0:
        return None
    ver = (buf[i + 1] >> 3) & 3
    layer = (buf[i + 1] >> 1) & 3
    if ver == 1 or layer != 1:
        return None
    bri = (buf[i + 2] >> 4) & 15
    sri = (buf[i + 2] >> 2) & 3
    if bri in (0, 15) or sri == 3:
        return None
    bitrate = (_MP3_BR_V1L3 if ver == 3 else _MP3_BR_V2L3)[bri] * 1000
    srate = _MP3_SR[sri] // (2 if ver == 2 else 1) if ver in (2, 3) else _MP3_SR[sri]
    if ver == 2 and sri in (3,):
        return None
    if ver == 3:
        pad = (buf[i + 2] >> 1) & 1
        return 144 * bitrate // srate + pad
    return 72 * bitrate // srate + ((buf[i + 2] >> 1) & 1)


def recover_mp3(data, spans, out_path, log):
    n = len(data)
    best = None
    for a, b in spans:
        i = a
        while i < min(b, n) - 4:
            L = mp3_frame_len(data, i)
            if L and 24 <= L <= 2048 and i + L <= n:
                # 链式验证 8 帧
                p, ok = i, 0
                while ok < 8 and p < b:
                    Ln = mp3_frame_len(data, p)
                    if not Ln:
                        break
                    p += Ln
                    ok += 1
                if ok >= 8:
                    best = (i, p)
                    break
            i += 1
        if best:
            break
    if not best:
        return None
    start, _ = best
    # 从 start 到所在 span 末尾逐帧走，输出全部完整帧
    out = bytearray()
    p = start
    a, b = max((s for s in spans if s[0] <= start < s[1]), default=(start, n))
    while p + 4 <= b:
        L = mp3_frame_len(data, p)
        if not L or p + L > b:
            break
        out += data[p:p + L]
        p += L
    if len(out) < 4096:
        return None
    with open(out_path, "wb") as fh:
        fh.write(out)
    return out_path, dict(frames_out_bytes=len(out), start_offset=start)


# ----------------------------------------------------------------------
# JPG：嵌入预览图雕刻
# ----------------------------------------------------------------------

def recover_jpg_previews(data, spans, out_dir, base, log):
    found = []
    for si, (a, b) in enumerate(spans):
        seg = data[a:b]
        i = 0
        while True:
            s = seg.find(b"\xff\xd8\xff", i)
            if s < 0:
                break
            e = s + 100
            while True:
                e = seg.find(b"\xff\xd9", e)
                if e < 0:
                    break
                cand = seg[s:e + 2]
                ok = _jpg_valid(cand)
                if ok:
                    found.append((a + s, cand, ok))
                    i = s + (e - s) + 2
                    break
                e += 2
            else:
                i = s + 2
                continue
            break
    outs = []
    for k, (off, blob, (w, h)) in enumerate(found):
        p = os.path.join(out_dir, "%s.preview%d_%dx%d.jpg" % (base, k, w, h))
        with open(p, "wb") as fh:
            fh.write(blob)
        outs.append((p, w, h))
        log("    预览图: %s (%dx%d)" % (os.path.basename(p), w, h))
    return outs


def _jpg_valid(blob):
    try:
        from PIL import Image
        import io
        im = Image.open(io.BytesIO(blob))
        im.load()
        return im.size
    except ImportError:
        if len(blob) < 1000:
            return None
        return (0, 0)   # 无 Pillow 时仅做尺寸下限检查
    except Exception:
        return None


# ----------------------------------------------------------------------
# WAV：重写 RIFF 头
# ----------------------------------------------------------------------

def recover_wav(data, spans, out_dir, base, log):
    """取最大明文区，按常见格式候选生成 WAV（实验性：采样率需人工挑选）"""
    a, b = max(spans, key=lambda s: s[1] - s[0])
    pcm = data[a:b]
    # 4 字节对齐（立体声 16bit 帧 = 4 字节）
    pcm = pcm[:len(pcm) // 4 * 4]
    outs = []
    for srate, ch in ((44100, 2), (48000, 2), (44100, 1), (48000, 1), (22050, 1)):
        hdr = b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVEfmt " + \
            struct.pack("<IHHIIHH", 16, 1, ch, srate, srate * ch * 2, ch * 2, 16) + \
            b"data" + struct.pack("<I", len(pcm))
        p = os.path.join(out_dir, "%s_%dHz_%dch.wav" % (base, srate, ch))
        with open(p, "wb") as fh:
            fh.write(hdr + pcm)
        outs.append(p)
    log("    WAV: 输出 %d 个候选（请试听挑选采样率正确的）" % len(outs))
    return outs


# ----------------------------------------------------------------------
# MP4/HEVC：NAL 提取
# ----------------------------------------------------------------------

def recover_mp4(data, spans, out_dir, base, log):
    """从明文区提取全部 [4B len][NAL] 单元为 Annex-B 素材流"""
    annexb = bytearray()
    counts = collections.Counter()
    total = 0
    for a, b in spans:
        p = a
        while p + 4 <= b:
            L = struct.unpack_from(">I", data, p)[0]
            if L < 2 or p + 4 + L > b or L > 8 * 1024 * 1024:
                p += 1
                continue
            nal = data[p + 4:p + 4 + L]
            t = (nal[0] >> 1) & 0x3F
            counts[t] += 1
            total += 1
            annexb += b"\x00\x00\x00\x01" + nal
            p += 4 + L
    p = os.path.join(out_dir, "%s_frames.h265" % base)
    with open(p, "wb") as fh:
        fh.write(annexb)
    log("    提取 %d 个 NAL（%s），保存为 %s" %
        (total, "HEVC(推测)" if total else "空", os.path.basename(p)))
    log("    提示：HEVC 素材流需要同源参考视频的参数集(VPS/SPS/PPS)才能装配播放；"
        "若流内含参数集可直接播放。可尝试: ffmpeg -f hevc -i 素材 -c copy out.mp4")
    return p, dict(nals=total, types=dict(counts))


# ----------------------------------------------------------------------
# 单文件分诊 + 恢复调度
# ----------------------------------------------------------------------

def process_file(path, out_dir, log):
    name = os.path.basename(path)
    base = os.path.splitext(name)[0]
    base = base.replace(".L0CK3D", "").replace(".LOCK3D", "")
    r = dict(file=name, verdict="未知", detail="")
    try:
        with open(path, "rb") as fh:
            d = fh.read()
    except OSError as e:
        r["verdict"] = "读取失败"
        r["detail"] = str(e)
        return r
    n = len(d)
    info = parse_container(d)
    if not info:
        r["verdict"] = "不是 .L0CK3D 容器（或结构不同）"
        return r
    r["size"] = n
    r["mode"] = info["mode_name"]
    r["orig_size"] = info["orig_size"]
    chunks = encrypted_chunks(info["data_end"], info["orig_size"], info["percent"]) \
        if info["mode"] == 0x25 else \
        ([(0, min(1048576, info["data_end"]))] if info["mode"] == 0x26 else [(0, info["data_end"])])
    spans = plaintext_spans(info["data_end"], chunks)
    plain_mb = sum(b - a for a, b in spans) / 1048576
    r["plain_mb"] = round(plain_mb, 1)
    log("[分诊] %s | %s | 原始 %.2fMB | 明文区 %.1fMB" %
        (name, info["mode_name"], info["orig_size"] / 1048576, plain_mb))

    if info["mode"] == 0x24:
        r["verdict"] = "❌ 整体加密（<1MB 档），无明文可救"
        r["detail"] = "只能依靠：NAS 快照 / Hyper Backup / 重新获取原文件"
        return r

    low = base.lower()
    KNOWN_EXTS = (".flac", ".mp3", ".wav", ".m4a", ".jpg", ".jpeg", ".png", ".gif",
                  ".bmp", ".mp4", ".mov", ".mkv", ".avi", ".pdf", ".docx", ".xlsx", ".pptx")
    ext = next((k for k in KNOWN_EXTS if k in low), os.path.splitext(base)[1].lower())
    recovered = []

    try:
        if ext in (".flac",):
            out = os.path.join(out_dir, base + ".recovered.flac")
            res = recover_flac(d, spans, out, log)
            if res:
                recovered.append(res[0])
                r["verdict"] = "✅ FLAC 重建成功"
                r["detail"] = "%d 帧, 约 %.0f 秒, %.1fMB" % (
                    res[1]["frames"], res[1]["duration"], res[1]["size"] / 1048576)
            else:
                r["verdict"] = "未找到可用的 FLAC 帧结构"
        elif ext == ".mp3":
            out = os.path.join(out_dir, base + ".recovered.mp3")
            res = recover_mp3(d, spans, out, log)
            if res:
                recovered.append(res[0])
                r["verdict"] = "✅ MP3 切头成功"
                r["detail"] = "自偏移 %d 起输出 %d 字节" % (res[1]["start_offset"], res[1]["frames_out_bytes"])
            else:
                r["verdict"] = "未找到 MP3 帧同步"
        elif ext == ".wav":
            outs = recover_wav(d, spans, out_dir, base, log)
            recovered.extend(outs)
            r["verdict"] = "✅ WAV 候选已生成（实验性）"
        elif ext in (".jpg", ".jpeg"):
            outs = recover_jpg_previews(d, spans, out_dir, base, log)
            if outs:
                recovered.extend([o[0] for o in outs])
                r["verdict"] = "✅ 恢复 %d 张嵌入预览图" % len(outs)
                r["detail"] = "；".join("%dx%d" % (w, h) for _, w, h in outs)
            else:
                r["verdict"] = "明文区未发现嵌入预览图"
        elif ext == ".mp4":
            res = recover_mp4(d, spans, out_dir, base, log)
            if res:
                recovered.append(res[0])
                r["verdict"] = "🟡 视频帧已提取（需装配）"
                r["detail"] = "%d 个 NAL；播放需同源参考视频的参数集" % res[1]["nals"]
            else:
                r["verdict"] = "明文区无视频帧"
        else:
            # 未知格式：尽力扫描明文区里的嵌入 JPEG
            outs = recover_jpg_previews(d, spans, out_dir, base, log)
            if outs:
                recovered.extend([o[0] for o in outs])
                r["verdict"] = "✅ 意外收获：%d 张嵌入图片" % len(outs)
            else:
                r["verdict"] = "格式未自动支持（明文区 %.1fMB 已保留扫描）" % plain_mb
    except Exception as e:
        r["verdict"] = "处理异常"
        r["detail"] = "%s: %s" % (type(e).__name__, e)
        log("    异常: %s" % traceback.format_exc().splitlines()[-1])

    r["outputs"] = recovered
    return r


# ----------------------------------------------------------------------
# 批量模式
# ----------------------------------------------------------------------

def batch(folder, out_dir, report_path):
    os.makedirs(out_dir, exist_ok=True)
    log = lambda m: print(m)
    files = []
    for root, _dirs, names in os.walk(folder):
        for nm in names:
            if nm.lower().endswith((".l0ck3d", ".lock3d")):
                files.append(os.path.join(root, nm))
    files.sort()
    log("找到 %d 个 .L0CK3D 文件\n" % len(files))
    results = []
    t0 = time.time()
    for k, p in enumerate(files, 1):
        print("[%d/%d] %s" % (k, len(files), os.path.basename(p)))
        try:
            results.append(process_file(p, out_dir, print))
        except Exception:
            results.append(dict(file=os.path.basename(p), verdict="处理异常",
                                detail=traceback.format_exc(limit=1)))
    ok = [r for r in results if str(r.get("verdict", "")).startswith(("✅", "🟡"))]
    md = ["# .L0CK3D 数据抢救报告", "",
          "- 扫描目录: `%s`" % folder,
          "- 文件总数: %d" % len(results),
          "- 有收获: %d ｜ 无法恢复: %d" % (len(ok), len(results) - len(ok)),
          "- 生成时间: %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
          "", "| 文件 | 大小 | 加密模式 | 判定 | 详情 |", "|---|---|---|---|---|"]
    for r in results:
        md.append("| %s | %s | %s | %s | %s |" % (
            r.get("file", "?"), "%.2fMB" % (r.get("size", 0) / 1048576),
            r.get("mode", "?"), r.get("verdict", "?"), r.get("detail", "")))
    md += ["", "## 恢复产物", ""]
    for r in results:
        for o in r.get("outputs", []) or []:
            md.append("- `%s`" % o)
    md += ["", "## 安全提醒", "",
           "1. 先把 NAS 断网、改密码，堵住入侵入口；",
           "2. 检查 DSM 快照与 Hyper Backup——有备份就能全部救回；",
           "3. 不要支付赎金；可提交样本到 NoMoreRansom / ID Ransomware；",
           "4. 本工具不会修改你的原始加密文件。"]
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    print("\n完成：%d 个文件，耗时 %.0f 秒" % (len(results), time.time() - t0))
    print("报告: %s" % report_path)
    print("产物目录: %s" % out_dir)


def main():
    ap = argparse.ArgumentParser(description="C3RB3R/.L0CK3D 勒索软件数据抢救工具")
    ap.add_argument("path", help="加密文件或包含 .L0CK3D 文件的文件夹")
    ap.add_argument("-o", "--out", default=None, help="产物输出目录（默认 <目标>_recovered）")
    ap.add_argument("--report", default=None, help="批量模式报告路径")
    args = ap.parse_args()
    if os.path.isdir(args.path):
        out = args.out or (args.path.rstrip("/\\") + "_recovered")
        rep = args.report or os.path.join(out, "报告.md")
        os.makedirs(out, exist_ok=True)
        batch(args.path, out, rep)
    else:
        out = args.out or os.path.dirname(os.path.abspath(args.path))
        os.makedirs(out, exist_ok=True)
        r = process_file(args.path, out, print)
        print("\n判定:", r.get("verdict"))
        if r.get("detail"):
            print("详情:", r["detail"])
        for o in r.get("outputs", []) or []:
            print("产物:", o)


if __name__ == "__main__":
    main()
