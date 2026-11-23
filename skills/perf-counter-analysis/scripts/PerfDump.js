"use strict";

// Reads performance counters of inmation objects from a dump (cdb JavaScript provider, loaded with .scriptload).
// Objects are found in inmation::model::_maps.path_objects_ (canonical path -> CObject). The hash list is walked with
// raw memory reads; every offset comes from the PDB type information, so no STL layout is hard-coded.
// Output: one '@@PERF|<kind>|...' line per fact (paths as UTF-8 hex), parsed by lib\PerfData.ps1.
// <req> is the index of the requested path (perfDump takes several paths, comma-separated hex, one map walk).
//   MAPS|<entries>|<walked>|<ms>                        size of path_objects_
//   MATCH|<req>|<obj>|<pathHex>|<class>|<hasPerf>|<items> object with the requested path (case-insensitive)
//   CAND|<req>|<pathHex>|<class>|<hasPerf>|<items>        similar paths when there is no exact match
//   DUMPED|<req>|<obj>                                    the object whose counters follow
//   ITEM|<code>|<n second>|<n minute>|<n hour>|<n day>    one counter and its buffer sizes
//   ROW|<code>|<timebase>|<t ms>|<sum>|<num>|<avg>|<min>|<max>
//   AGG|<code>|<timebase>|<aggregate>|<t ms>|<value>      only when the five buffers of a timebase differ in length
//   LIST|<pathHex>|<class>|<items>                        objects with counters (perfList)
//   LISTED|<shown>|<with counters>|<ms>
//   WARN|<text>, ERR|<text>, DONE|<ms>

function initializeScript() { return [new host.apiVersionSupport(1, 7)]; }

function emit(s) { host.diagnostics.debugLog("@@PERF|" + s + "\n"); }

function toHex(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) { var b = bytes[i] & 0xff; s += (b < 16 ? "0" : "") + b.toString(16); }
    return s;
}

function fromHex(hex) {
    var a = [];
    for (var i = 0; i + 1 < hex.length; i += 2) a.push(parseInt(hex.substr(i, 2), 16));
    return a;
}

function foldAscii(b) { return (b >= 65 && b <= 90) ? b + 32 : b; }

function num(x) { return (typeof x === "number") ? x : x.asNumber(); }

function u64(lo, hi) { return hi * 4294967296 + lo; }

var dv = new DataView(new ArrayBuffer(8));
function f64(lo, hi) { dv.setUint32(0, lo, true); dv.setUint32(4, hi, true); return dv.getFloat64(0, true); }

function fmt(v) { return (v === undefined) ? "" : String(v); }

function findField(type, name) {
    var fields = type.fields;
    if (Object.getOwnPropertyNames(fields).indexOf(name) >= 0) return { offset: num(fields[name].offset), type: fields[name].type };
    var bases = [];
    try { bases = type.baseClasses; } catch (e) { bases = []; }
    for (var b of bases) {
        var r = findField(b.type, name);
        if (r) return { offset: num(b.offset) + r.offset, type: r.type };
    }
    return null;
}

function fieldAt(type, path) {
    var off = 0, t = type;
    for (var part of path.split(".")) {
        var r = findField(t, part);
        if (!r) throw new Error("field '" + part + "' of '" + path + "' not found in " + t.name + " (unsupported build layout)");
        off += r.offset;
        t = r.type;
    }
    return { offset: off, type: t };
}

var L = null;

function layout(moduleName) {
    if (L && L.module === moduleName) return L;
    var maps = host.getModuleSymbol(moduleName, "inmation::model::_maps");
    var list = maps.path_objects_._List._Mypair._Myval2;
    var nodeType = list._Myhead.dereference().targetType;
    var objType = host.getModuleType(moduleName, "inmation::model::CObject");
    var clsType = host.getModuleType(moduleName, "inmation::model::CClass");
    var perfType = host.getModuleType(moduleName, "inmation::model::CObjectPerformance");
    var itemType = host.getModuleType(moduleName, "inmation::model::CObjectPerformance::item");
    var exType = host.getModuleType(moduleName, "inmation::model::prpPerformanceEx");
    var first = fieldAt(exType, "ex.buffer._Mypair._Myval2._Myfirst");
    var vt = null;
    try { vt = first.type.baseType; } catch (e) { vt = null; }
    var prop = fieldAt(itemType, "prop");
    var next = fieldAt(nodeType, "_Next");
    L = {
        module: moduleName,
        list: list,
        ptr: num(next.type.size),
        next: next.offset,
        keyData: fieldAt(nodeType, "_Myval.first._Mydata").offset,
        keySize: fieldAt(nodeType, "_Myval.first._Mysize").offset,
        obj: fieldAt(nodeType, "_Myval.second._Ptr").offset,
        perf: fieldAt(objType, "performance_._Mypair._Myval2").offset,
        classdef: fieldAt(objType, "classdef_").offset,
        code: fieldAt(clsType, "code_").offset,
        items: fieldAt(perfType, "items._Mypair._Myval2._Myval2._Mysize").offset,
        prop: prop.offset,
        propSlot: num(prop.type.size) / 20,
        first: first.offset,
        last: fieldAt(exType, "ex.buffer._Mypair._Myval2._Mylast").offset,
        vtSize: vt ? num(vt.size) : 16,
        vOff: vt ? fieldAt(vt, "v").offset : 0,
        tOff: vt ? fieldAt(vt, "t").offset : 8
    };
    return L;
}

function readU32(addr, count) { return host.memory.readMemoryValues(host.Int64(addr), count, 4, false); }

function readPtr(addr) {
    if (L.ptr === 4) return readU32(addr, 1)[0];
    var w = readU32(addr, 2);
    return u64(w[0], w[1]);
}

// Word (pointer-size value) at byte offset 'off' of a block read with readU32.
function word(w, off) { return (L.ptr === 4) ? w[off / 4] : u64(w[off / 4], w[off / 4 + 1]); }

function walkPaths(visit) {
    var headAddr = num(L.list._Myhead.address);
    var size = num(L.list._Mysize);
    var span = Math.max(L.next, L.keyData, L.keySize, L.obj) + L.ptr;
    var cur = readPtr(headAddr + L.next), n = 0;
    while (cur !== headAddr && cur !== 0 && n <= size) {
        var w = readU32(cur, span / 4);
        visit(word(w, L.keyData), word(w, L.keySize), word(w, L.obj));
        cur = word(w, L.next);
        n++;
    }
    if (n !== size) emit("WARN|path_objects_ walk visited " + n + " of " + size + " entries (map changing at dump time?)");
    return { size: size, walked: n };
}

function objectFacts(obj) {
    var perf = readPtr(obj + L.perf);
    var cls = readPtr(obj + L.classdef);
    var code = cls ? readU32(cls + L.code, 1)[0] : 0;
    var items = perf ? readPtr(perf + L.items) : 0;
    return { perf: perf, cls: code, items: items };
}

function readKey(data, size) { return size ? host.memory.readMemoryValues(host.Int64(data), size, 1, false) : []; }

function lastSegment(bytes) {
    var i = bytes.length - 1;
    while (i >= 0 && bytes[i] !== 47) i--;
    return bytes.slice(i + 1);
}

function contains(hay, needle) {
    if (needle.length === 0 || needle.length > hay.length) return false;
    outer: for (var i = 0; i + needle.length <= hay.length; i++) {
        for (var j = 0; j < needle.length; j++) { if (foldAscii(hay[i + j]) !== needle[j]) continue outer; }
        return true;
    }
    return false;
}

function dumpCounters(req, obj) {
    var o = host.createPointerObject(host.Int64(obj), L.module, "inmation::model::CObject *").dereference();
    var perf = o.performance_._Mypair._Myval2.dereference();
    emit("DUMPED|" + req + "|" + obj.toString(16));
    for (var it of perf.items) {
        var code = num(it.first);
        var base = num(it.second.address) + L.prop;
        var slots = [];
        for (var s = 0; s < 20; s++) slots.push(readPtr(base + s * L.propSlot));
        var counts = [], tables = [];
        for (var tb = 0; tb < 4; tb++) {
            var cols = [], times = [], aligned = true;
            for (var ag = 0; ag < 5; ag++) {
                var p = slots[tb * 5 + ag];
                var vals = [], ts = [];
                if (p) {
                    var fa = readPtr(p + L.first), la = readPtr(p + L.last);
                    var cnt = (la - fa) / L.vtSize;
                    if (cnt > 0 && cnt < 100000) {
                        var w = readU32(fa, cnt * L.vtSize / 4);
                        for (var k = 0; k < cnt; k++) {
                            var b = k * L.vtSize / 4;
                            vals.push(f64(w[b + L.vOff / 4], w[b + L.vOff / 4 + 1]));
                            ts.push(u64(w[b + L.tOff / 4], w[b + L.tOff / 4 + 1]));
                        }
                    }
                }
                cols.push(vals);
                times.push(ts);
                if (ag > 0 && (ts.length !== times[0].length || (ts.length && (ts[0] !== times[0][0] || ts[ts.length - 1] !== times[0][ts.length - 1])))) aligned = false;
            }
            counts.push(times[0].length);
            tables.push({ cols: cols, times: times, aligned: aligned });
        }
        emit("ITEM|" + code + "|" + counts.join("|"));
        for (var tb = 0; tb < 4; tb++) {
            var t = tables[tb];
            if (t.aligned) {
                for (var k = 0; k < t.times[0].length; k++) {
                    emit("ROW|" + code + "|" + tb + "|" + t.times[0][k] + "|" + fmt(t.cols[0][k]) + "|" + fmt(t.cols[1][k]) + "|" + fmt(t.cols[2][k]) + "|" + fmt(t.cols[3][k]) + "|" + fmt(t.cols[4][k]));
                }
            }
            else {
                emit("WARN|buffers of counter " + code + " timebase " + tb + " differ in length");
                for (var ag = 0; ag < 5; ag++) {
                    for (var k = 0; k < t.times[ag].length; k++) emit("AGG|" + code + "|" + tb + "|" + ag + "|" + t.times[ag][k] + "|" + fmt(t.cols[ag][k]));
                }
            }
        }
    }
}

function sameBytes(a, b) {
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) { if (a[i] !== b[i]) return false; }
    return true;
}

function editDistance(a, b) {
    var prev = [], cur;
    for (var j = 0; j <= b.length; j++) prev.push(j);
    for (var i = 1; i <= a.length; i++) {
        cur = [i];
        for (var j = 1; j <= b.length; j++) cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)));
        prev = cur;
    }
    return prev[b.length];
}

// pathsHex: requested paths as UTF-8 hex, separated by commas. One walk of the map serves all of them.
function perfDump(moduleName, pathsHex, maxCandidates) {
    var started = Date.now();
    try {
        layout(moduleName);
        var wants = pathsHex.split(",").filter(function (h) { return h.length > 0; }).map(function (h) { return fromHex(h).map(foldAscii); });
        var lasts = wants.map(lastSegment);
        // Parent path including the trailing '/': siblings are candidates for a typo in the last segment.
        var parents = wants.map(function (w, i) { return w.slice(0, w.length - lasts[i].length); });
        var matches = wants.map(function () { return []; });
        var near = wants.map(function () { return []; });
        var r = walkPaths(function (data, size, obj) {
            var key = null, folded = null;
            var fold = function () { if (folded === null) { key = readKey(data, size); folded = key.map(foldAscii); } return folded; };
            var matched = false;
            for (var w = 0; w < wants.length; w++) {
                if (size === wants[w].length && sameBytes(fold(), wants[w])) { matches[w].push({ key: key, obj: obj }); matched = true; }
            }
            if (matched || size >= 4096) return;
            for (var w = 0; w < wants.length; w++) {
                if (near[w].length >= 2000) continue;
                var f = fold();
                var seg = lastSegment(f);
                var exactSeg = sameBytes(seg, lasts[w]);
                if (!exactSeg && near[w].length >= 500) continue;
                var sibling = parents[w].length > 1 && f.length > parents[w].length && f.length - seg.length === parents[w].length && sameBytes(f.slice(0, parents[w].length), parents[w]);
                if (exactSeg || (lasts[w].length >= 3 && contains(key, lasts[w])) || sibling) near[w].push({ key: key, obj: obj, rank: exactSeg ? 0 : (sibling ? 1 : 2), dist: sibling ? editDistance(seg, lasts[w]) : 0 });
            }
        });
        emit("MAPS|" + r.size + "|" + r.walked + "|" + (Date.now() - started));
        var dumped = {};
        for (var w = 0; w < wants.length; w++) {
            for (var m of matches[w]) {
                var f = objectFacts(m.obj);
                emit("MATCH|" + w + "|" + m.obj.toString(16) + "|" + toHex(m.key) + "|" + f.cls + "|" + (f.perf ? 1 : 0) + "|" + f.items);
            }
            for (var m of matches[w]) {
                if (!objectFacts(m.obj).perf) continue;
                if (dumped[m.obj]) emit("DUMPED|" + w + "|" + m.obj.toString(16));
                else { dumpCounters(w, m.obj); dumped[m.obj] = true; }
                break;
            }
            if (matches[w].length === 0) {
                // Exact last segment first, then siblings by similarity of the name, then other similar paths;
                // within each group objects with counters first, then shorter paths.
                var cands = near[w].map(function (c) { c.facts = objectFacts(c.obj); return c; });
                cands.sort(function (a, b) { return a.rank - b.rank || a.dist - b.dist || (b.facts.perf ? 1 : 0) - (a.facts.perf ? 1 : 0) || a.key.length - b.key.length; });
                for (var c of cands.slice(0, maxCandidates)) {
                    emit("CAND|" + w + "|" + toHex(c.key) + "|" + c.facts.cls + "|" + (c.facts.perf ? 1 : 0) + "|" + c.facts.items);
                }
            }
        }
    }
    catch (e) { emit("ERR|" + e.message); }
    emit("DONE|" + (Date.now() - started));
}

function perfList(moduleName, filterHex, maxRows) {
    var started = Date.now();
    try {
        layout(moduleName);
        var filter = fromHex(filterHex).map(foldAscii);
        var shown = 0, withPerf = 0;
        var r = walkPaths(function (data, size, obj) {
            var f = objectFacts(obj);
            if (!f.perf) return;
            withPerf++;
            if (shown >= maxRows) return;
            var key = readKey(data, size);
            if (filter.length && !contains(key, filter)) return;
            emit("LIST|" + toHex(key) + "|" + f.cls + "|" + f.items);
            shown++;
        });
        emit("MAPS|" + r.size + "|" + r.walked + "|" + (Date.now() - started));
        emit("LISTED|" + shown + "|" + withPerf + "|" + (Date.now() - started));
    }
    catch (e) { emit("ERR|" + e.message); }
    emit("DONE|" + (Date.now() - started));
}
