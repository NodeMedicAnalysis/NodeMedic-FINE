import * as underscore from 'underscore';
import { F, Literal, ExternalFunction } from './Flib';
import { State, describeState, Context, initState, setC, IID, 
         setTc, createTc, getTc, createTcFromSourceLocation } from './State';
import { WLiteral, WGetFieldPre, WGetField, WInvokeFunPre,
         WInvokeFun, WBinary, WBinaryPre, Wrapped, Unwrapped,
         WEvalPre, WEval, WPutFieldPre, WPutField, WUnaryPre,
         WUnary, WConditional, WWrite, WFunctionEnter, WFunctionExit, WEndExpr } from './Wrapper';
import { TGetField, TCall, TBinary, TEval, TUnary, TCallPre, TPutField, 
         TEvalPre, TWrite, SINKS, CORE_SINKS } from './Taint';
import { Tracer } from './Trace';
import { isGhostFunction, dispatchGhostFunction } from './GhostFunction';
import { Config } from './Config';
import { IM } from './modules/ImportedModule';


export class Instrumentation {
    s: State;
    config: Config;
    t: Tracer;
    accessed_attrs: Array<string>;
    constructor(config: Config) {
        this.s = initState();
        this.config = config;
        this.t = new Tracer(this.config);
        this.accessed_attrs = [];
        return this;
    }
    scriptEnter(originalFileName: string) {
        this.t.explain(`Entering script: ${originalFileName}`);
        let s1 = this.s;
        this.s = s1;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with scriptEnter');
    }
    literal(value: Literal): Object {
        this.t.explain(`Wrapping literal: ${this.t.inspect(value, this.s)}`);
        let s1 = this.s;
        let [s2, valP] = F.eitherThrow(WLiteral(s1, value));
        let s3 = setC(s2, Context.Unset);
        this.s = s3;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with literal');
        return {value: valP};
    }
    write(lhs: Wrapped, val: any): Object {
        this.t.explain(`Write: ${this.t.inspect(lhs, this.s)} = ${this.t.inspect(val, this.s)}`);
        let s1 = this.s;
        let [s2, valP] = F.eitherThrow(WWrite(s1, val));
        let s3 = setC(s2, Context.Unset);
        let s4 = F.eitherThrow(TWrite(s3, valP));
        this.s = s4;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with write');
        return {val: valP};
    }
    getFieldPre(base: Wrapped, offset: Wrapped): Object {
        this.t.explain(`getFieldPre on ${this.t.inspect(base, this.s)}.${this.t.inspect(offset, this.s)}`);
        let s1 = this.s;
        let [s2, result] = F.eitherThrow(WGetFieldPre(s1, base, offset));
        let baseP: Unwrapped = result[0];
        let offsetP: Unwrapped = result[1];
        let s3 = setC(s2, Context.Unset);
        if (this.config.HONEYOBJECTS && baseP instanceof Object && !baseP.hasOwnProperty(offsetP)) {
            baseP[offsetP] = function() { return baseP };
        }
        this.s = s3;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with getFieldPre');
        return {base: baseP, offset: offsetP};
    }
    getField(base: Unwrapped, offset: Unwrapped, value: Unwrapped, sourceLocation: string): Object {
        // Before: u3 := u1.u2
        if (!this.accessed_attrs.includes(offset)){
            this.accessed_attrs.push(offset);
        }
        this.t.explain(`getField on ${this.t.inspect(base, this.s)}.${this.t.inspect(offset, this.s)} = ${this.t.inspect(value, this.s)}`);
        if (typeof value == 'function' && (F.isUndefinedOrNull(value.name) || value.name == '')) {
            Object.defineProperty(value, 'name', {value: offset, enumerable: false});
        }
        let s1 = setTc(this.s, createTcFromSourceLocation(sourceLocation));
        let [s2, result] = F.eitherThrow(WGetField(s1, base, offset, value));
        let x1: Wrapped = result[0];
        let x2: Wrapped = result[1];
        let r: Wrapped = result[2];
        let s3 = F.eitherThrow(TGetField(s2, x1, x2, r));
        let s4 = setC(s3, Context.Unset);
        this.s = s4;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with getField');
        return {base: x1, offset: x2, result: r};
    }
    putFieldPre(base: Wrapped, offset: Wrapped, value: Wrapped): Object {
        this.t.explain(`putFieldPre on ${this.t.inspect(base, this.s)}.${this.t.inspect(offset, this.s)} = ${this.t.inspect(value, this.s)}`);
        let s1 = this.s;
        let [s2, result] = F.eitherThrow(WPutFieldPre(s1, base, offset, value));
        let baseP: Unwrapped = result[0];
        let offsetP: Unwrapped = result[1];
        let valueP: Wrapped | Unwrapped = result[2];
        let s3 = setC(s2, Context.Unset);
        this.s = s3;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with putFieldPre');
        return {base: baseP, offset: offsetP, value: valueP};
    }
    putField(base: Unwrapped, offset: Unwrapped, value: Wrapped, sourceLocation: string): Object {
        // Before: u3 := u1.u2
        this.t.explain(`putField on ${this.t.inspect(base, this.s)}.${this.t.inspect(offset, this.s)} = ${this.t.inspect(value, this.s)}`);
        let s1 = setTc(this.s, createTcFromSourceLocation(sourceLocation));
        let [s2, result] = F.eitherThrow(WPutField(s1, base, offset, value));
        let x1: Wrapped = result[0];
        let x2: Wrapped = result[1];
        let valueP: Wrapped | Unwrapped = result[2];
        let s3 = F.eitherThrow(TPutField(s2, x1, x2, valueP));
        let s4 = setC(s3, Context.Unset);
        this.s = s4;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with putField');
        return {base: x1, offset: x2, val: valueP};
    }
    invokeFunPre(
        f: Function,
        base: Wrapped,
        args: Wrapped[],
        isMethod: boolean,
        isConstructor: boolean,
        isExternal: boolean,
        iid: IID,
        originalScriptPath: string | null,
        cov_info : Array<any>,
        global_cov_info : Array<any>,
        sourceLocation: string,
    ): Object {
        let reset_branches = false;
        let hasName = underscore.has(f, 'name');
        if (typeof f == 'function' && hasName) {
            switch (f.name) {

                /* With Jalangi we offer a way to provide coverage information to the fuzzer */
                case '__fuzzer_reset_get_fields__': {
                    this.accessed_attrs = [];
                    break;
                }
                case '__fuzzer_get_fields__': {
                    args[0] = this.accessed_attrs;
                    break;
                }

                case '__fuzzer_get_branches__': {
                    args[0] = cov_info;
                    break;
                }

                case '__fuzzer__reset_branches__': {
                    reset_branches = true;
                    break;
                }

                case '__fuzzer_get_global_coverage__': {
                    args[0] = global_cov_info;
                    break;
                }

                case require.name:
                    // Wrapper for require
                    f = IM.moduleImport.bind(null, originalScriptPath);
                    Object.defineProperty(f, 'name', {value: 'require'});
                    // require is always external
                    isExternal = true;
                    break;
                case Function.prototype.call.name:
                case Function.prototype.apply.name:
                case Function.prototype.bind.name:
                    // Call, apply, and bind are external 
                    // only if the base is external or native function
                    isExternal = (typeof base === "function" && F.isNativeFunction(base)) || IM.isExternalModule(base);
                    break;
                default:
                    break;
            }
        }
        // A native function must be external
        let isNative = isExternal && F.isNativeFunction(f);
        let callType = isNative ? 'Native' : (isExternal ? 'External' : 'Internal');
        if (isMethod) {
            this.t.explain(`invokeFunPre on [${this.t.inspect(base, this.s)}/this] ${this.t.inspect(f, this.s)} ${this.t.inspect(Array.from(args), this.s)} [${callType}]`);
        } else {
            this.t.explain(`invokeFunPre on ${this.t.inspect(f, this.s)} ${this.t.inspect(Array.from(args), this.s)} [${callType}]`);
        }
        let s1 = setTc(this.s, createTcFromSourceLocation(sourceLocation));
        let s2 = F.eitherThrow(TCallPre(s1, f, base, args));
        if (hasName && isGhostFunction(f.name)) {
            // Don't perform unwrapping for ghost functions
            let s3 = dispatchGhostFunction(s2, f.name, args, this.config, this.t);
            let s4 = setC(s3, Context.Unset);
            this.s = s4;
            this.t.explain(describeState(this.s, this.config.EXPLAIN));
            this.t.explain('Done with invokeFunPre');
            return {f: f, base: base, args: args};
        }
        let [s3, result] = F.eitherThrow(
            WInvokeFunPre(iid, s2, f, base, args, isMethod, isExternal, isNative)
        );
        let fP: Unwrapped = result[0];
        let baseP: Unwrapped = result[1];
        let argsP: Unwrapped = result[2];
        let s4 = setC(s3, Context.Unset);
        this.s = s4;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with invokeFunPre');
        return {f: fP, base: baseP, args: argsP, reset_branches: reset_branches};
    }
    functionEnter(f: Function) {
        this.t.explain(`functionEnter on ${this.t.inspect(f, this.s)}`);
        let s = this.s;
        let s1 = F.eitherThrow(WFunctionEnter(s, f));
        let s2 = setC(s1, Context.Unset);
        this.s = s2;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with functionEnter');
    }
    functionExit(threwException: boolean) {
        this.t.explain(`functionExit`);
        let s = this.s;
        let s1 = F.eitherThrow(WFunctionExit(s, threwException));
        let s2 = setC(s1, Context.Unset);
        this.s = s2;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with functionExit');
    }
    invokeFun(
        f: Function, 
        base: Unwrapped, 
        args: Unwrapped[],
        result: Unwrapped,
        isConstructor: boolean, 
        isMethod: boolean,
        isExternal: boolean,
        iid: IID
    ): Object {
        // An internal function can't be native
        let s1 = this.s;
        let isNative = isExternal && F.isNativeFunction(f);
        if (isMethod) {
            this.t.explain(`invokeFun on [${this.t.inspect(base, s1)}/this] ${this.t.inspect(f, this.s)} ${this.t.inspect(Array.from(args), this.s)} = ${this.t.inspect(result, this.s)}`);
        } else {
            this.t.explain(`invokeFun on ${this.t.inspect(f, s1)} ${this.t.inspect(Array.from(args), this.s)} = ${this.t.inspect(result, this.s)}`);
        }
        // Don't do anything for ghost functions
        if (underscore.has(f, 'name') && isGhostFunction(f.name)) {
            let s2 = setC(s1, Context.Unset);
            this.s = s2;
            this.t.explain(describeState(this.s, this.config.EXPLAIN));
            this.t.explain('Done with invokeFun');
            return {f: f, base: base, args: args, result: result};
        }
        // Propagate sinks for external functions
        if (this.config.SINK_PROPAGATION) {
            if ((isExternal || this.config.AGGRESSIVE_SINK_PROPAGATION) && F.isFunction(result)) {
                let propagateSink = false;
                for (var i = 0; i < args.length; i++) {
                    CORE_SINKS.forEach((sink: string, func: Function) => {
                        if (args[i] === func) {
                            propagateSink = true;
                            SINKS.set(result, sink);
                        }
                    })
                    if (propagateSink)
                        break;
                }
            }
        }
        let [s2, res] = F.eitherThrow(WInvokeFun(iid, s1, f, base, args, result, isMethod, isNative, isExternal));
        let fP: Wrapped = res[0];
        let baseP: Wrapped = res[1];
        let argsP: Wrapped[] = res[2];
        let resultP: Wrapped = res[3];
        if (isExternal) {
            var s3 = F.eitherThrow(TCall(s2, fP as ExternalFunction, baseP, argsP, resultP, isExternal));
        } else {
            var s3 = F.eitherThrow(TCall(s2, fP as Function, baseP, argsP, resultP, isExternal));
        }
        let s4 = setC(s3, Context.Unset);
        this.s = s4;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with invokeFun');
        return {f: fP, base: baseP, args: argsP, result: resultP};
    }
    binaryPre(op: string, x1: Wrapped, x2: Wrapped): Object {
        this.t.explain(`binaryPre on ${this.t.inspect(x1, this.s)} ${op} ${this.t.inspect(x2, this.s)}`);
        let s1 = this.s;
        let [s2, result] = F.eitherThrow(WBinaryPre(s1, x1, x2));
        let u1: Unwrapped = result[0];
        let u2: Unwrapped = result[1];
        let s3 = setC(s2, Context.Unset);
        this.s = s3;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with binaryPre');
        return {left: u1, right: u2};
    }
    binary(op: string, u1: Unwrapped, u2: Unwrapped, u3: Unwrapped, sourceLocation: string): Object {
        this.t.explain(`binary on ${this.t.inspect(u1, this.s)} ${op} ${this.t.inspect(u2, this.s)} = ${this.t.inspect(u3, this.s)}`);
        // Before: u3 := u1 op u2
        let s1 = setTc(this.s, createTcFromSourceLocation(sourceLocation));
        let [s2, result] = F.eitherThrow(WBinary(s1, u1, u2, u3));
        let x1: Wrapped = result[0];
        let x2: Wrapped = result[1];
        let r: Wrapped = result[2];
        let s3 = F.eitherThrow(TBinary(s2, op, x1, x2, r));
        let s4 = setC(s3, Context.Unset);
        this.s = s4;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with binary');
        return {left: x1, right: x2, result: r};
    }
    unaryPre(op: string, x: Wrapped) : Object {
        this.t.explain(`unaryPre on ${this.t.inspect(x, this.s)} ${op}`);
        let s = this.s;
        let [s1, result] = F.eitherThrow(WUnaryPre(s, x));
        let s2 = setC(s1, Context.Unset);
        this.s = s2;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with unaryPre');
        return {left: result[0]};
    }
    unary(op: string, u1: Unwrapped, u2: Unwrapped, sourceLocation: string): Object  {
        // Before: u2 := op u1
        this.t.explain(`unary on ${this.t.inspect(u1, this.s)} ${op} = ${this.t.inspect(u2, this.s)}`);
        let s1 = setTc(this.s, createTcFromSourceLocation(sourceLocation));
        let [s2, result] = F.eitherThrow(WUnary(s1, u1, u2));
        let x: Wrapped = result[0];
        let r: Wrapped = result[1];
        let s3 = F.eitherThrow(TUnary(s2, x, r));
        let s4 = setC(s3, Context.Unset);
        this.s = s4;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with unary');
        return {result: r};
    }
    instrumentCodePre(code: Wrapped, isInternal: boolean): Object {
        this.t.explain(`instrumentCodePre on ${this.t.inspect(code, this.s)} [${isInternal ? "Internal" : "External"}]`);
        let s1 = this.s;
        let [s2, result] = F.eitherThrow(WEvalPre(s1, code, isInternal));
        let ucode: string = result[0] as string;
        let s3 = setC(s2, Context.Unset);
        let is_string;
        try {
            ucode.includes('');
            is_string = true;
        } catch {
            is_string = false;
        }
        // rewrite so taint still propagates for Eval
        if (!is_string || !ucode.includes('// JALANGI DO NOT INSTRUMENT')) {
            let [s4, modCode] = F.eitherThrow(TEvalPre(s3, ucode, code));
            this.s = s4;
            this.t.explain(describeState(this.s, this.config.EXPLAIN));
            this.t.explain('Done with instrumentCodePre');
            return {code: modCode[0]};
        } else {
            this.s = s3;
            this.t.explain(describeState(this.s, this.config.EXPLAIN));
            this.t.explain('Done with instrumentCodePre');
            return {code: ucode};
        }
    }
    instrumentCode(newCode: string): Object {
        this.t.explain(`instrumentCode on ${this.t.inspect(newCode, this.s)}`);
        let s1 = this.s;
        let [s2, result] = F.eitherThrow(WEval(s1, newCode));
        let wcode: Wrapped = result[0];
        let s3 = F.eitherThrow(TEval(s2, wcode));
        let s4 = setC(s3, Context.Unset);
        this.s = s4;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with instrumentCode');
        return {newCode: newCode};
    }
    conditional(condResult: Wrapped): Object {
        this.t.explain(`conditional on ${this.t.inspect(condResult, this.s)}`);
        let s1 = this.s;
        let [s2, result] = F.eitherThrow(WConditional(s1, condResult));
        let ucondResult: boolean | Object = result[0];
        let s3 = setC(s2, Context.CondExpr);
        this.s = s3;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with conditional');
        return {result: ucondResult};
    }
    endExpression() {
        this.t.explain(`endExpression`);
        let s1 = this.s;
        let s2 = F.eitherThrow(WEndExpr(s1));
        let s3 = setC(s2, Context.Unset);
        this.s = s3;
        this.t.explain(describeState(this.s, this.config.EXPLAIN));
        this.t.explain('Done with endExpression');
    }
}
