#!/usr/bin/env python3
"""Translates nxnative's FRAME_STEP stubs (dm/games/*/patches.py) into C# for MeloNX.Native.Prep: src/MeloNX.Native.Prep/Rewriter/FrameSteps.Generated.cs.
The stubs are small Python functions that assemble words into the patch area; this translator covers the subset they use (assignments, for loops over constant tuples,
lists and enumerate, if / elif / else, assert, the nso_asm encoders, ctx.here / emit / site / put / state / render_scale) and stops on anything else. The module-level
helpers a stub calls (ASTRAL CHAIN's signed, width, relocate) are ported by hand in FrameSteps.cs; their sources are checked against HELPERS here.
tools/native/frame_step_test.py checks every translated stub against the Python one.
Usage: gen_frame_steps.py <nxnative checkout> <out.cs>"""
import ast, glob, hashlib, inspect, importlib.util, os, sys

# Module-level helpers ported by hand (FrameSteps.cs): name → (C# name, SHA-256 of the Python source the port was made from)
HELPERS = {
    'signed': ('Signed', 'f538bca1c560bc6c3fddc9d05003ee4ad0672cafd557d5b4a2e15d2e80371ff0'),
    'width': ('Width', '2322c6efeab5c6252f5b3216775df82aa6d434a35bcd15e63a2224de65df74c7'),
    'relocate': ('Relocate', 'bedb9f2d887db940b455f755a257241aee03a89d3d8235108af13596efe7aa8d'),
}
ENCODERS = {'B', 'ADRP', 'LDRX', 'STRX', 'STP_PRE', 'LDP_POST', 'STP', 'LDP', 'ADDI', 'SUBI', 'ADDR', 'STUR', 'LDUR', 'BR', 'BLR', 'BEQ', 'BRK', 'CMPR', 'MRS_TPIDRRO'}
CTX = {'here': 'Here', 'emit': 'Emit', 'site': 'Site', 'put': 'Put', 'state': 'State', 'render_scale': 'RenderScale'}


class Unsupported(Exception):
    pass


def src_hash(fn): return hashlib.sha256(inspect.getsource(fn).encode()).hexdigest()


def cs_str(s): return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def cs_type(v):
    if isinstance(v, bool): raise Unsupported('bool')
    if isinstance(v, int): return 'long'
    if isinstance(v, str): return 'string'
    if isinstance(v, (tuple, list)):
        if not v: return 'long[]'
        ts = [cs_type(x) for x in v]
        if all(t == 'long' for t in ts): return 'long[]'
        return '(' + ', '.join(ts) + ')'
    raise Unsupported(f'value {v!r}')


def record_type(v):
    """a tuple of scalars as a C# tuple type (an element of a table the stub loops over)"""
    return '(' + ', '.join(cs_type(x) for x in v) + ')'


def cs_value(v):
    if isinstance(v, int): return f'0x{v:x}L' if v >= 0 else f'-0x{-v:x}L'
    if isinstance(v, str): return cs_str(v)
    raise Unsupported(f'value {v!r}')


class Gen:
    def __init__(self, mod, gid, fn):
        self.mod, self.gid, self.fn = mod, gid, fn
        self.aliases = {}      # local name → ctx attribute (here, emit, ...)
        self.vars = {}         # local name → C# type
        self.globals = {}      # module-level data used → (C# field name, declaration)
        self.lines = []
        self.depth = 3

    def w(self, s): self.lines.append('    ' * self.depth + s)

    def global_data(self, name):
        v = getattr(self.mod, name)
        field = f'D{self.gid}_{name}'
        if field not in self.globals:
            if isinstance(v, (tuple, list)) and v and all(isinstance(x, int) for x in v):
                decl = f'private static readonly long[] {field} = {{ ' + ', '.join(cs_value(x) for x in v) + ' };'
                self.globals[field] = (decl, 'long[]', 'long')
            elif isinstance(v, (tuple, list)) and v and all(isinstance(x, tuple) for x in v):
                t = record_type(v[0])
                items = ',\n            '.join('(' + ', '.join(cs_value(y) for y in x) + ')' for x in v)
                decl = f'private static readonly {t}[] {field} =\n        {{\n            {items},\n        }};'
                self.globals[field] = (decl, f'{t}[]', t)
            else: raise Unsupported(f'module data {name}')
        return field

    # ---- expressions → (C# text, type) ----
    def expr(self, n):
        if isinstance(n, ast.Constant):
            return cs_value(n.value), cs_type(n.value)
        if isinstance(n, ast.Name):
            if n.id in self.vars: return n.id, self.vars[n.id]
            if n.id in self.aliases and self.aliases[n.id] == 'state': return 'ctx.State', 'long'
            if n.id == 'NOP': return '(long)NOP', 'long'
            if hasattr(self.mod, n.id) and not callable(getattr(self.mod, n.id)):
                f = self.global_data(n.id); return f, self.globals[f][1]
            raise Unsupported(f'name {n.id}')
        if isinstance(n, ast.Attribute):
            if isinstance(n.value, ast.Name) and n.value.id == 'ctx' and n.attr in ('state', 'render_scale'): return f'ctx.{CTX[n.attr]}', 'long'
            raise Unsupported(ast.dump(n))
        if isinstance(n, ast.BinOp):
            a, ta = self.expr(n.left); b, tb = self.expr(n.right)
            if isinstance(n.op, ast.Add) and 'string' in (ta, tb): return f'({a} + {b})', 'string'
            op = {ast.BitOr: '|', ast.BitAnd: '&', ast.LShift: '<<', ast.RShift: '>>', ast.Add: '+', ast.Sub: '-', ast.Mult: '*', ast.BitXor: '^'}.get(type(n.op))
            if isinstance(n.op, ast.FloorDiv): return f'FloorDiv({a}, {b})', 'long'
            if not op: raise Unsupported(ast.dump(n.op))
            if op in ('<<', '>>'): b = f'(int)({b})'
            return f'({a} {op} {b})', 'long'
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.USub):
            a, t = self.expr(n.operand); return f'(-{a})', t
        if isinstance(n, ast.Compare) and len(n.ops) == 1:
            a, _ = self.expr(n.left); b, _ = self.expr(n.comparators[0])
            op = {ast.Eq: '==', ast.NotEq: '!=', ast.Lt: '<', ast.LtE: '<=', ast.Gt: '>', ast.GtE: '>='}.get(type(n.ops[0]))
            if not op: raise Unsupported(ast.dump(n))
            return f'({a} {op} {b})', 'bool'
        if isinstance(n, ast.Subscript):
            a, t = self.expr(n.value); i, _ = self.expr(n.slice)
            if t == 'dict': return f'{a}[{i}]', 'long'
            return f'{a}[(int)({i})]', 'long'
        if isinstance(n, ast.Dict):
            items = ', '.join(f'[{self.expr(k)[0]}] = {self.expr(v)[0]}' for k, v in zip(n.keys, n.values))
            return f'new Dictionary<long, long> {{ {items} }}', 'dict'
        if isinstance(n, (ast.List, ast.Tuple)):
            return 'new long[] { ' + ', '.join(self.expr(e)[0] for e in n.elts) + ' }', 'long[]'
        if isinstance(n, ast.Call): return self.call(n)
        raise Unsupported(ast.dump(n))

    def call(self, n):
        f = n.func
        if isinstance(f, ast.Attribute) and f.attr == 'from_bytes' and getattr(f.value, 'id', '') == 'int':
            b = n.args[0]
            if isinstance(b, ast.Call) and isinstance(b.func, ast.Attribute) and b.func.attr == 'fromhex' and n.args[1].value == 'little':
                return f'FromHexLE({self.expr(b.args[0])[0]})', 'long'
        if isinstance(f, ast.Attribute) and f.attr == 'hex' and isinstance(f.value, ast.Call):
            inner = f.value
            if isinstance(inner.func, ast.Attribute) and inner.func.attr == 'pack' and getattr(inner.func.value, 'id', '') == 'struct' and inner.args[0].value == '<I':
                return f'Hex32({self.expr(inner.args[1])[0]})', 'string'
        args = [self.expr(a)[0] for a in n.args]
        # ctx.<x>() or an alias of it
        name = None
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == 'ctx': name = f.attr
        elif isinstance(f, ast.Name) and f.id in self.aliases: name = self.aliases[f.id]
        if name == 'here': return 'ctx.Here()', 'long'
        if name in ('emit', 'site', 'put'): return f'ctx.{CTX[name]}(' + ', '.join(args) + ')', 'void'
        if isinstance(f, ast.Name):
            if f.id in ENCODERS:
                cast = [f'(int)({a})' for a in args]
                if f.id in ('B', 'BEQ'): cast = args
                elif f.id == 'ADRP': cast = [f'(int)({args[0]})'] + args[1:]
                elif f.id in ('ADDI', 'SUBI'): cast = [f'(int)({args[0]})', f'(int)({args[1]})', args[2]] + [f'(int)({a})' for a in args[3:]]
                elif f.id in ('LDRX', 'STRX'): cast = [f'(int)({args[0]})', f'(int)({args[1]})'] + args[2:]
                elif f.id in ('STP_PRE', 'LDP_POST', 'STP', 'LDP'): cast = [f'(int)({a})' for a in args[:3]] + args[3:]
                elif f.id in ('STUR', 'LDUR'): cast = [f'(int)({a})' for a in args[:2]] + args[2:]
                return f'(long){f.id}(' + ', '.join(cast) + ')', 'long'
            if f.id in HELPERS:
                cs, _ = HELPERS[f.id]
                return f'{cs}(' + ', '.join(args) + ')', 'list' if f.id == 'relocate' else 'long'
            if f.id == 'len': return f'{args[0]}.Length', 'long'
        if isinstance(f, ast.Attribute) and f.attr == 'hex' and isinstance(f.value, ast.Call):
            inner = f.value
            if isinstance(inner.func, ast.Attribute) and inner.func.attr == 'pack' and getattr(inner.func.value, 'id', '') == 'struct' and inner.args[0].value == '<I':
                return f'Hex32({self.expr(inner.args[1])[0]})', 'string'
        if isinstance(f, ast.Attribute) and f.attr == 'from_bytes' and getattr(f.value, 'id', '') == 'int':
            b = n.args[0]
            if isinstance(b, ast.Call) and isinstance(b.func, ast.Attribute) and b.func.attr == 'fromhex' and n.args[1].value == 'little':
                return f'FromHexLE({self.expr(b.args[0])[0]})', 'long'
        raise Unsupported(ast.dump(n)[:200])

    # ---- statements ----
    def assign(self, target, value_cs, t):
        if isinstance(target, ast.Name):
            if target.id in self.vars: self.w(f'{target.id} = {value_cs};')
            else:
                self.vars[target.id] = t
                self.w(f'{ "var" if t in ("dict", "list") else t} {target.id} = {value_cs};')
            return
        if isinstance(target, ast.Subscript):
            a, _ = self.expr(target.value); i, _ = self.expr(target.slice)
            self.w(f'{a}[{i}] = {value_cs};'); return
        if isinstance(target, ast.Attribute) and getattr(target.value, 'id', '') == 'ctx' and target.attr == 'render_scale':
            self.w(f'ctx.RenderScale = (int)({value_cs});'); return
        raise Unsupported(ast.dump(target))

    def stmt(self, s):
        if isinstance(s, ast.Expr):
            if isinstance(s.value, ast.Constant): return   # a docstring
            c, _ = self.expr(s.value); self.w(c + ';'); return
        if isinstance(s, ast.Assign) and len(s.targets) == 1:
            tg = s.targets[0]
            if isinstance(tg, ast.Tuple) and isinstance(s.value, ast.Tuple) and all(isinstance(v, ast.Attribute) and getattr(v.value, 'id', '') == 'ctx' for v in s.value.elts):
                for name, v in zip(tg.elts, s.value.elts): self.aliases[name.id] = v.attr
                return
            if isinstance(tg, ast.Tuple):
                raise Unsupported('tuple assignment')
            c, t = self.expr(s.value); self.assign(tg, c, t); return
        if isinstance(s, ast.AugAssign):
            c, _ = self.expr(s.value)
            op = {ast.Add: '+=', ast.Sub: '-=', ast.BitOr: '|='}[type(s.op)]
            self.w(f'{s.target.id} {op} {c};'); return
        if isinstance(s, ast.Assert):
            c, _ = self.expr(s.test); self.w(f'RewriteAssertion.Check({c});'); return
        if isinstance(s, ast.If):
            c, _ = self.expr(s.test); self.w(f'if ({c})'); self.block(s.body)
            orelse = s.orelse
            while len(orelse) == 1 and isinstance(orelse[0], ast.If):
                c, _ = self.expr(orelse[0].test); self.w(f'else if ({c})'); self.block(orelse[0].body); orelse = orelse[0].orelse
            if orelse: self.w('else'); self.block(orelse)
            return
        if isinstance(s, ast.For): return self.for_(s)
        raise Unsupported(ast.dump(s)[:200])

    def block(self, body):
        self.w('{'); self.depth += 1
        saved = dict(self.vars)
        for s in body: self.stmt(s)
        self.vars = saved
        self.depth -= 1; self.w('}')

    def for_(self, s):
        it = s.iter
        saved = dict(self.vars)
        enum = isinstance(it, ast.Call) and getattr(it.func, 'id', '') == 'enumerate'
        if enum: it = it.args[0]
        if isinstance(it, ast.Tuple) and it.elts and all(isinstance(e, ast.Tuple) for e in it.elts):
            vals = [tuple(ast.literal_eval(self.const_expr(x)) for x in e.elts) for e in it.elts]
            et = record_type(vals[0]); seq = f'new {et}[] {{ ' + ', '.join('(' + ', '.join(self.expr(x)[0] for x in e.elts) + ')' for e in it.elts) + ' }'
        elif isinstance(it, (ast.Tuple, ast.List)):
            et = 'long'; seq = 'new long[] { ' + ', '.join(self.expr(e)[0] for e in it.elts) + ' }'
        else:
            seq, t = self.expr(it)
            et = {'list': 'long', 'long[]': 'long'}.get(t) or (self.globals[seq][2] if seq in self.globals else None)
            if et is None: raise Unsupported(f'for over {t}')
        item = f'__it{self.depth}'
        if enum:
            i, v = s.target.elts
            self.w(f'for (int {i.id} = 0; {i.id} < {seq}.Length; {i.id}++)'); self.w('{'); self.depth += 1
            self.vars[i.id] = 'long'; self.vars[v.id] = et
            self.w(f'{et} {v.id} = {seq}[{i.id}];')
        else:
            self.w(f'foreach (var {item} in {seq})'); self.w('{'); self.depth += 1
            if isinstance(s.target, ast.Tuple):
                types = et[1:-1].split(', ')
                for name, t in zip(s.target.elts, types): self.vars[name.id] = t
                self.w('var (' + ', '.join(e.id for e in s.target.elts) + f') = {item};')
            else:
                self.vars[s.target.id] = et; self.w(f'{et} {s.target.id} = {item};')
        for st in s.body: self.stmt(st)
        self.depth -= 1; self.w('}')
        self.vars = saved

    def const_expr(self, e):
        """a constant element of a literal tuple (ints, strings, and expressions of them) as Python source for literal_eval"""
        try: return repr(eval(compile(ast.Expression(e), '<const>', 'eval'), {}, {}))
        except Exception: return '0'


def main():
    repo, out = sys.argv[1], sys.argv[2]
    sys.path.insert(0, os.path.join(repo, 'dm', 'tools'))
    games = os.path.join(repo, 'dm', 'games')
    methods, fields, regs = [], [], []
    for path in sorted(glob.glob(os.path.join(games, '*', 'patches.py'))):
        gid = os.path.basename(os.path.dirname(path))
        spec = importlib.util.spec_from_file_location(f'p_{gid}', path); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        for bid, fn in getattr(m, 'FRAME_STEP', {}).items():
            tree = ast.parse(inspect.getsource(fn)).body[0]
            for name in {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id in HELPERS}:
                want = HELPERS[name][1]
                got = src_hash(getattr(m, name))
                if want is not None and want != got:
                    sys.exit(f'[RED] {gid} {name} changed upstream ({got}): port it again in FrameSteps.cs and update HELPERS')
            g = Gen(m, gid, fn)
            for s in tree.body: g.stmt(s)
            mname = f'Fs{gid}_{bid[:8]}'
            methods.append(f'        // {gid}/patches.py frame_step, build {bid}\n        private static void {mname}(IFrameStepContext ctx)\n        {{\n' + '\n'.join(g.lines) + '\n        }\n')
            fields += [d for d, _, _ in g.globals.values()]
            regs.append(f'            ports["{bid}"] = new("{src_hash(fn)}", {mname});')
    cs = ['// <auto-generated> by tools/native/gen_frame_steps.py from nxnative\'s dm/games/*/patches.py FRAME_STEP stubs. Do not edit: generate it again.',
          'using System.Collections.Generic;', 'using static MeloNX.Native.Prep.Rewriter.NsoAsm;', '', 'namespace MeloNX.Native.Prep.Rewriter', '{',
          '    public static partial class FrameSteps', '    {', '        static partial void Register(Dictionary<string, Port> ports)', '        {'] + regs + ['        }', '']
    cs += methods + ['        ' + f for f in fields] + ['    }', '}', '']
    open(out, 'w').write('\n'.join(cs))
    print(f'{out}: {len(regs)} frame step stubs')


if __name__ == '__main__':
    main()
