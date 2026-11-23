use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub enum IfpsAction {
    Exec {
        exe: String,
        params: String,
        target_dir: String,
        desc: String,
    },
    ArcExtract {
        archive: String,
        out_dir: String,
        delete_after: bool,
        password: String,
    },
}

#[derive(Debug, Clone)]
enum IfpsVal {
    Str(String),
    Int(i64),
    Bool(bool),
    Ref(u32),
    None,
}

impl IfpsVal {
    fn as_string(&self) -> String {
        match self {
            IfpsVal::Str(s) => s.clone(),
            _ => String::new(),
        }
    }

    fn as_bool(&self) -> bool {
        match self {
            IfpsVal::Bool(b) => *b,
            IfpsVal::Int(n) => *n != 0,
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
struct StackSlot {
    id: u32,
    val: IfpsVal,
}

#[derive(Debug, Clone)]
struct ProcInfo {
    ext: bool,
    name: String,
    off: usize,
    len: usize,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        let s = self.data.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let s = self.data.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn i32(&mut self) -> Option<i32> {
        self.u32().map(|v| v as i32)
    }

    fn u64(&mut self) -> Option<u64> {
        let s = self.data.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        Some(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
}

// RemObjects PascalScript base type IDs (uPSUtils.pas)
const BT_U8: u8 = 1;
const BT_S8: u8 = 2;
const BT_U16: u8 = 3;
const BT_S16: u8 = 4;
const BT_U32: u8 = 5;
const BT_S32: u8 = 6;
const BT_SINGLE: u8 = 7;
const BT_DOUBLE: u8 = 8;
const BT_EXTENDED: u8 = 9;
const BT_STRING: u8 = 10;
const BT_RECORD: u8 = 11;
const BT_ARRAY: u8 = 12;
const BT_POINTER: u8 = 13;
const BT_PCHAR: u8 = 14;
const BT_RESPTR: u8 = 15;
const BT_VARIANT: u8 = 16;
const BT_S64: u8 = 17;
const BT_CHAR: u8 = 18;
const BT_WIDESTRING: u8 = 19;
const BT_WIDECHAR: u8 = 20;
const BT_PROCPTR: u8 = 21;
const BT_STATICARRAY: u8 = 22;
const BT_SET: u8 = 23;
const BT_CURRENCY: u8 = 24;
const BT_CLASS: u8 = 25;
const BT_INTERFACE: u8 = 26;
const BT_NOTIFVAR: u8 = 27;
const BT_UNICODESTRING: u8 = 28;

fn decode_latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

fn decode_utf16le(b: &[u8]) -> String {
    let u16s: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

fn read_const_val(
    r: &mut Reader<'_>,
    tidx: usize,
    types: &[u8],
    set_sizes: &HashMap<usize, usize>,
) -> Option<IfpsVal> {
    let &bt = types.get(tidx)?;
    match bt {
        BT_U8 => {
            let v = r.u8()?;
            Some(IfpsVal::Bool(v != 0))
        }
        BT_S8 | BT_CHAR => Some(IfpsVal::Int(r.u8()? as i8 as i64)),
        BT_U16 | BT_WIDECHAR => Some(IfpsVal::Int(r.u16()? as i64)),
        BT_S16 => Some(IfpsVal::Int(r.u16()? as i16 as i64)),
        BT_U32 | BT_SINGLE => Some(IfpsVal::Int(r.u32()? as i64)),
        BT_S32 => Some(IfpsVal::Int(r.i32()? as i64)),
        BT_DOUBLE | BT_S64 | BT_CURRENCY => Some(IfpsVal::Int(r.u64()? as i64)),
        BT_EXTENDED => {
            r.bytes(10)?;
            Some(IfpsVal::None)
        }
        BT_STRING | BT_PCHAR => {
            let ln = r.u32()? as usize;
            if ln > 4 * 1024 * 1024 {
                return None;
            }
            let b = r.bytes(ln)?;
            Some(IfpsVal::Str(decode_latin1(b)))
        }
        BT_UNICODESTRING | BT_WIDESTRING => {
            let ln = r.u32()? as usize;
            if ln > 4 * 1024 * 1024 {
                return None;
            }
            let b = r.bytes(ln)?;
            Some(IfpsVal::Str(decode_utf16le(b)))
        }
        BT_SET => {
            let sz = *set_sizes.get(&tidx).unwrap_or(&4);
            r.bytes(sz)?;
            Some(IfpsVal::None)
        }
        BT_POINTER | BT_RESPTR | BT_VARIANT | BT_PROCPTR | BT_CLASS | BT_INTERFACE
        | BT_NOTIFVAR | BT_RECORD | BT_ARRAY | BT_STATICARRAY => {
            // Fallback for rare pointer/empty constants
            Some(IfpsVal::None)
        }
        _ => None,
    }
}

fn skip_attrs(
    r: &mut Reader<'_>,
    types: &[u8],
    set_sizes: &HashMap<usize, usize>,
) -> Option<()> {
    let cnt = r.u32()? as usize;
    if cnt > 4096 {
        return None;
    }
    for _ in 0..cnt {
        let nlen = r.u32()? as usize;
        r.bytes(nlen)?;
        let fcnt = r.u32()? as usize;
        for _ in 0..fcnt {
            let ft = r.u32()? as usize;
            read_const_val(r, ft, types, set_sizes)?;
        }
    }
    Some(())
}

#[derive(Debug, Clone)]
enum VarSpec {
    Var(u32),
    Const(IfpsVal),
    IndexedConst(u32, u32),
    IndexedVar(u32, u32),
}

fn read_varspec(
    r: &mut Reader<'_>,
    types: &[u8],
    set_sizes: &HashMap<usize, usize>,
) -> Option<VarSpec> {
    let kind = r.u8()?;
    match kind {
        0 => Some(VarSpec::Var(r.u32()?)),
        1 => {
            let tidx = r.u32()? as usize;
            let val = read_const_val(r, tidx, types, set_sizes)?;
            Some(VarSpec::Const(val))
        }
        2 => {
            let v = r.u32()?;
            let idx = r.u32()?;
            Some(VarSpec::IndexedConst(v, idx))
        }
        3 => {
            let v = r.u32()?;
            let iv = r.u32()?;
            Some(VarSpec::IndexedVar(v, iv))
        }
        _ => None,
    }
}

fn peek_varspec_valid(
    data: &[u8],
    pos: usize,
    types: &[u8],
    set_sizes: &HashMap<usize, usize>,
) -> bool {
    let mut r = Reader::new(data, pos);
    let Some(kind) = r.u8() else {
        return false;
    };
    match kind {
        0 => r.u32().is_some(),
        1 => {
            let Some(tidx) = r.u32() else {
                return false;
            };
            (tidx as usize) < types.len()
                && read_const_val(&mut r, tidx as usize, types, set_sizes).is_some()
        }
        2 | 3 => r.u32().is_some() && r.u32().is_some(),
        _ => false,
    }
}

fn resolve_val(spec: &VarSpec, vars: &HashMap<u32, IfpsVal>) -> IfpsVal {
    match spec {
        VarSpec::Const(v) => v.clone(),
        VarSpec::Var(id) => {
            match vars.get(id) {
                Some(IfpsVal::Ref(target)) => vars.get(target).cloned().unwrap_or(IfpsVal::None),
                Some(v) => v.clone(),
                None => IfpsVal::None,
            }
        }
        VarSpec::IndexedConst(_, _) | VarSpec::IndexedVar(_, _) => IfpsVal::None,
    }
}

fn resolve_slot_val(slot: &StackSlot, vars: &HashMap<u32, IfpsVal>) -> IfpsVal {
    match &slot.val {
        IfpsVal::Ref(target) => vars.get(target).cloned().unwrap_or(IfpsVal::None),
        IfpsVal::None => vars.get(&slot.id).cloned().unwrap_or(IfpsVal::None),
        v => v.clone(),
    }
}

fn write_var(id: u32, val: IfpsVal, vars: &mut HashMap<u32, IfpsVal>, stack: &mut [StackSlot]) {
    let target = match vars.get(&id) {
        Some(IfpsVal::Ref(t)) => *t,
        _ => id,
    };
    vars.insert(target, val.clone());
    for slot in stack.iter_mut().rev() {
        if slot.id == target {
            slot.val = val;
            break;
        }
    }
}

/// Parses an Inno Setup `CompiledCode.bin` (IFPS v18-v23) and extracts ordered `ISExec` and
/// nested `ISArcExtract` post-unpack actions from `CURSTEPCHANGED` (or any internal proc calling them).
pub fn extract_post_unpack_actions(compiled_code_path: &Path) -> (Vec<IfpsAction>, Vec<String>) {
    let mut notes = Vec::new();
    let Ok(data) = fs::read(compiled_code_path) else {
        return (Vec::new(), notes);
    };
    if data.len() < 28 || &data[0..4] != b"IFPS" {
        return (Vec::new(), notes);
    }

    let mut r = Reader::new(&data, 4);
    let Some(ver) = r.u32() else { return (Vec::new(), notes); };
    let Some(n_types) = r.u32() else { return (Vec::new(), notes); };
    let Some(n_procs) = r.u32() else { return (Vec::new(), notes); };
    let Some(n_vars) = r.u32() else { return (Vec::new(), notes); };
    let Some(_main_proc) = r.u32() else { return (Vec::new(), notes); };
    let Some(_import_sz) = r.u32() else { return (Vec::new(), notes); };

    // 1. Parse type table
    let mut types = Vec::with_capacity(n_types as usize);
    let mut set_sizes = HashMap::new();
    for ti in 0..(n_types as usize) {
        let Some(raw) = r.u8() else { return (Vec::new(), notes); };
        let exported = (raw & 0x80) != 0;
        let bt = raw & 0x7F;
        match bt {
            BT_CLASS | BT_PROCPTR => {
                let Some(ln) = r.u32() else { return (Vec::new(), notes); };
                if r.bytes(ln as usize).is_none() { return (Vec::new(), notes); }
            }
            BT_INTERFACE => {
                if r.bytes(16).is_none() { return (Vec::new(), notes); }
            }
            BT_SET => {
                let Some(bsz) = r.u32() else { return (Vec::new(), notes); };
                let byte_sz = if bsz > 0 { ((bsz + 7) / 8) as usize } else { 4 };
                set_sizes.insert(ti, byte_sz);
            }
            BT_ARRAY => {
                if r.u32().is_none() { return (Vec::new(), notes); }
            }
            BT_STATICARRAY => {
                if r.u32().is_none() || r.u32().is_none() { return (Vec::new(), notes); }
                if ver >= 22 && r.u32().is_none() { return (Vec::new(), notes); }
            }
            BT_RECORD => {
                let Some(fc) = r.u32() else { return (Vec::new(), notes); };
                for _ in 0..fc {
                    if r.u32().is_none() { return (Vec::new(), notes); }
                }
            }
            _ => {}
        }
        if exported {
            let Some(ln) = r.u32() else { return (Vec::new(), notes); };
            if r.bytes(ln as usize).is_none() { return (Vec::new(), notes); }
        }
        types.push(bt);
        if ver >= 21 && skip_attrs(&mut r, &types, &set_sizes).is_none() {
            return (Vec::new(), notes);
        }
    }

    // 2. Parse procedure table
    let mut procs = Vec::with_capacity(n_procs as usize);
    for _ in 0..(n_procs as usize) {
        let Some(flags) = r.u8() else { return (Vec::new(), notes); };
        let ext = (flags & 1) != 0;
        let mut name = String::new();
        let mut off = 0usize;
        let mut len = 0usize;

        if ext {
            let Some(nlen) = r.u8() else { return (Vec::new(), notes); };
            let Some(nb) = r.bytes(nlen as usize) else { return (Vec::new(), notes); };
            name = decode_latin1(nb);
            if (flags & 2) != 0 {
                let Some(dlen) = r.u32() else { return (Vec::new(), notes); };
                let Some(db) = r.bytes(dlen as usize) else { return (Vec::new(), notes); };
                if name.is_empty() {
                    let mut parts = db.split(|&b| b == 0);
                    let _ = parts.next();
                    if let Some(fn_bytes) = parts.next() {
                        name = decode_latin1(fn_bytes);
                    }
                }
            }
        } else {
            let Some(o) = r.u32() else { return (Vec::new(), notes); };
            let Some(l) = r.u32() else { return (Vec::new(), notes); };
            off = o as usize;
            len = l as usize;
            if (flags & 2) != 0 {
                let Some(nlen) = r.u32() else { return (Vec::new(), notes); };
                let Some(nb) = r.bytes(nlen as usize) else { return (Vec::new(), notes); };
                name = decode_latin1(nb);
                let Some(dlen) = r.u32() else { return (Vec::new(), notes); };
                if r.bytes(dlen as usize).is_none() { return (Vec::new(), notes); }
            }
        }
        if (flags & 4) != 0 && ver >= 21 && skip_attrs(&mut r, &types, &set_sizes).is_none() {
            return (Vec::new(), notes);
        }
        procs.push(ProcInfo { ext, name, off, len });
    }

    // 3. Skip global variables
    for _ in 0..(n_vars as usize) {
        if r.u32().is_none() { return (Vec::new(), notes); }
        let Some(vflags) = r.u8() else { return (Vec::new(), notes); };
        if (vflags & 1) != 0 {
            let Some(ln) = r.u32() else { return (Vec::new(), notes); };
            if r.bytes(ln as usize).is_none() { return (Vec::new(), notes); }
        }
    }
    let code_base = r.pos;

    let expand_id = procs
        .iter()
        .position(|p| p.ext && p.name.eq_ignore_ascii_case("EXPANDCONSTANT"))
        .map(|i| i as u32);
    let is_exec_id = procs
        .iter()
        .position(|p| p.ext && p.name.eq_ignore_ascii_case("ISExec"))
        .map(|i| i as u32);
    let is_arc_id = procs
        .iter()
        .position(|p| p.ext && p.name.eq_ignore_ascii_case("ISArcExtract"))
        .map(|i| i as u32);

    if is_exec_id.is_none() && is_arc_id.is_none() {
        return (Vec::new(), notes);
    }

    let max_end = procs
        .iter()
        .filter(|p| !p.ext && p.len > 0)
        .map(|p| p.off + p.len)
        .max()
        .unwrap_or(0);
    let base = if max_end <= data.len() && (code_base + max_end) > data.len() {
        0usize
    } else {
        code_base
    };

    // Prioritize CURSTEPCHANGED; if absent, scan all non-empty internal procs
    let target_procs: Vec<&ProcInfo> = {
        let cur: Vec<&ProcInfo> = procs
            .iter()
            .filter(|p| !p.ext && p.len > 0 && p.name.eq_ignore_ascii_case("CURSTEPCHANGED"))
            .collect();
        if !cur.is_empty() {
            cur
        } else {
            procs.iter().filter(|p| !p.ext && p.len > 0).collect()
        }
    };

    let mut actions = Vec::new();
    for proc_info in target_procs {
        let start = base + proc_info.off;
        let end = (start + proc_info.len).min(data.len());
        if start >= end {
            continue;
        }
        let mut proc_actions = scan_proc_bytecode(
            &data[start..end],
            &types,
            &set_sizes,
            expand_id,
            is_exec_id,
            is_arc_id,
        );
        actions.append(&mut proc_actions);
    }

    if !actions.is_empty() {
        let exec_n = actions
            .iter()
            .filter(|a| matches!(a, IfpsAction::Exec { .. }))
            .count();
        let arc_n = actions
            .iter()
            .filter(|a| matches!(a, IfpsAction::ArcExtract { .. }))
            .count();
        notes.push(format!(
            "[IFPS] Decoded IFPS v{ver} CompiledCode.bin -> {exec_n} ISExec + {arc_n} ISArcExtract action(s)."
        ));
    }

    (actions, notes)
}

fn scan_proc_bytecode(
    code: &[u8],
    types: &[u8],
    set_sizes: &HashMap<usize, usize>,
    expand_id: Option<u32>,
    is_exec_id: Option<u32>,
    is_arc_id: Option<u32>,
) -> Vec<IfpsAction> {
    let mut actions = Vec::new();
    let mut r = Reader::new(code, 0);
    let mut vars: HashMap<u32, IfpsVal> = HashMap::new();
    let mut stack: Vec<StackSlot> = Vec::new();
    let mut next_slot_id: u32 = 0x6000_0001;
    let mut calibrated = false;

    while r.remaining() > 0 {
        let op_pos = r.pos;
        let Some(op) = r.u8() else { break; };

        match op {
            // CM_A (Assign): dst, src
            0x00 => {
                let Some(dst) = read_varspec(&mut r, types, set_sizes) else {
                    r.pos = op_pos + 1;
                    continue;
                };
                let Some(src) = read_varspec(&mut r, types, set_sizes) else {
                    r.pos = op_pos + 1;
                    continue;
                };
                let val = resolve_val(&src, &vars);
                if let VarSpec::Var(dst_id) = dst {
                    // Self-calibrate stack slot numbering on the first stack-var assignment
                    if !calibrated && dst_id >= 0x6000_0000 && !stack.is_empty() {
                        let top_idx = stack.len() - 1;
                        let expected = stack[top_idx].id;
                        if dst_id != expected && dst_id >= 0x6000_0000 && dst_id < 0x6000_1000 {
                            let delta = dst_id as i64 - expected as i64;
                            for sl in &mut stack {
                                sl.id = (sl.id as i64 + delta) as u32;
                            }
                            next_slot_id = (next_slot_id as i64 + delta) as u32;
                        }
                        calibrated = true;
                    }
                    write_var(dst_id, val, &mut vars, &mut stack);
                }
            }
            // CM_CA (Calculate): calc_op: u8, dst, src
            0x01 => {
                let Some(calc_op) = r.u8() else { break; };
                let Some(dst) = read_varspec(&mut r, types, set_sizes) else {
                    r.pos = op_pos + 1;
                    continue;
                };
                let Some(src) = read_varspec(&mut r, types, set_sizes) else {
                    r.pos = op_pos + 1;
                    continue;
                };
                if calc_op == 0 {
                    // String concatenation: dst := dst + src
                    if let VarSpec::Var(dst_id) = dst {
                        let lhs = resolve_val(&VarSpec::Var(dst_id), &vars);
                        let rhs = resolve_val(&src, &vars);
                        if let (IfpsVal::Str(a), IfpsVal::Str(b)) = (lhs, rhs) {
                            write_var(dst_id, IfpsVal::Str(format!("{a}{b}")), &mut vars, &mut stack);
                        }
                    }
                }
            }
            // CM_P (Push): val
            0x02 => {
                let Some(src) = read_varspec(&mut r, types, set_sizes) else {
                    r.pos = op_pos + 1;
                    continue;
                };
                let val = resolve_val(&src, &vars);
                let id = next_slot_id;
                next_slot_id = next_slot_id.wrapping_add(1);
                vars.insert(id, val.clone());
                stack.push(StackSlot { id, val });
            }
            // CM_PV (PushVar): ref to var
            0x03 => {
                let Some(src) = read_varspec(&mut r, types, set_sizes) else {
                    r.pos = op_pos + 1;
                    continue;
                };
                let val = match src {
                    VarSpec::Var(target_id) => IfpsVal::Ref(target_id),
                    other => resolve_val(&other, &vars),
                };
                let id = next_slot_id;
                next_slot_id = next_slot_id.wrapping_add(1);
                vars.insert(id, val.clone());
                stack.push(StackSlot { id, val });
            }
            // CM_Po (Pop)
            0x04 => {
                if let Some(popped) = stack.pop() {
                    next_slot_id = popped.id;
                }
            }
            // CM_C (Call): proc_no: u32
            0x05 => {
                let Some(proc_no) = r.u32() else { break; };
                let slen = stack.len();

                if expand_id == Some(proc_no) && slen >= 2 {
                    // stack[slen - 1] = result ref, stack[slen - 2] = arg0 string
                    let arg0 = resolve_slot_val(&stack[slen - 2], &vars);
                    if let IfpsVal::Ref(res_target) = stack[slen - 1].val {
                        write_var(res_target, arg0, &mut vars, &mut stack);
                    }
                } else if is_exec_id == Some(proc_no) && slen >= 9 {
                    // ISExec(CurComponent, PctOfTotal, SpecTime, ExeName, Parameters, TargetDir, OutputStr, Show): Boolean
                    // Stack top-down: [top]=Result, [top-1]=p0, [top-2]=p1, [top-3]=p2,
                    //                 [top-4]=ExeName, [top-5]=Parameters, [top-6]=TargetDir, [top-7]=OutputStr, [top-8]=Show
                    let exe = resolve_slot_val(&stack[slen - 5], &vars).as_string();
                    let params = resolve_slot_val(&stack[slen - 6], &vars).as_string();
                    let target_dir = resolve_slot_val(&stack[slen - 7], &vars).as_string();
                    let desc = resolve_slot_val(&stack[slen - 8], &vars).as_string();
                    if !exe.trim().is_empty() {
                        actions.push(IfpsAction::Exec {
                            exe,
                            params,
                            target_dir,
                            desc,
                        });
                    }
                } else if is_arc_id == Some(proc_no) && slen >= 11 {
                    // ISArcExtract(CurComp, Pct, InName, OutPath, ExtractedPath, DeleteInFile, Password, CfgFile, WorkPath, ExtractPCF): Boolean
                    // Stack top-down: [top]=Result, [top-1]=p0, [top-2]=p1, [top-3]=InName,
                    //                 [top-4]=OutPath, [top-5]=ExtractedPath, [top-6]=DeleteInFile, [top-7]=Password
                    let archive = resolve_slot_val(&stack[slen - 4], &vars).as_string();
                    let out_dir = resolve_slot_val(&stack[slen - 5], &vars).as_string();
                    let delete_after = resolve_slot_val(&stack[slen - 7], &vars).as_bool();
                    let password = resolve_slot_val(&stack[slen - 8], &vars).as_string();
                    if !archive.trim().is_empty() {
                        actions.push(IfpsAction::ArcExtract {
                            archive,
                            out_dir,
                            delete_after,
                            password,
                        });
                    }
                }
            }
            // CM_G (Goto), CM_FG (FlagGoto), CM_PopJump, CM_PopPopJump: i32
            0x06 | 0x0F | 0x16 | 0x17 => {
                if r.i32().is_none() { break; }
            }
            // CM_CG (CondGoto), CM_CNG (CondNotGoto): i32, VarSpec
            0x07 | 0x08 => {
                if r.i32().is_none() { break; }
                if read_varspec(&mut r, types, set_sizes).is_none() {
                    r.pos = op_pos + 1;
                }
            }
            // CM_R (Ret), CM_Nop (0xFF)
            0x09 | 0xFF => {}
            // CM_ST (SetStackType): var: u32, type: u32
            0x0A => {
                if r.u32().is_none() || r.u32().is_none() { break; }
            }
            // CM_PT (PushType): type: u32
            0x0B => {
                if r.u32().is_none() { break; }
                let id = next_slot_id;
                next_slot_id = next_slot_id.wrapping_add(1);
                vars.insert(id, IfpsVal::None);
                stack.push(StackSlot {
                    id,
                    val: IfpsVal::None,
                });
            }
            // CM_CO (Compare): cmp_op: u8, dst, lhs, rhs
            0x0C => {
                if r.u8().is_none() { break; }
                if read_varspec(&mut r, types, set_sizes).is_none()
                    || read_varspec(&mut r, types, set_sizes).is_none()
                    || read_varspec(&mut r, types, set_sizes).is_none()
                {
                    r.pos = op_pos + 1;
                }
            }
            // CM_CV (CallVar), CM_N (Not), CM_Inc, CM_Dec, CM_Neg, CM_SetZ: 1 VarSpec
            0x0D | 0x12 | 0x14 | 0x15 | 0x18 | 0x19 => {
                if read_varspec(&mut r, types, set_sizes).is_none() {
                    r.pos = op_pos + 1;
                }
            }
            // CM_SF (SetFlag): VarSpec, negate: u8
            0x0E => {
                if read_varspec(&mut r, types, set_sizes).is_none() || r.u8().is_none() {
                    r.pos = op_pos + 1;
                }
            }
            // CM_P2 (PushEH): 4 * u32
            0x10 => {
                if r.bytes(16).is_none() { break; }
            }
            // CM_P2E (PopEH): u8
            0x11 => {
                if r.u8().is_none() { break; }
            }
            // CM_SPC (SetCopyPointer): 2 VarSpecs (with safe 1-VarSpec fallback)
            0x13 => {
                if read_varspec(&mut r, types, set_sizes).is_none() {
                    r.pos = op_pos + 1;
                    continue;
                }
                if peek_varspec_valid(code, r.pos, types, set_sizes) {
                    let _ = read_varspec(&mut r, types, set_sizes);
                }
            }
            // Unknown opcode: step forward cleanly without losing stack tracking
            _ => {}
        }
    }

    actions
}
