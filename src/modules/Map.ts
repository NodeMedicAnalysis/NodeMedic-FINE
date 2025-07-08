import { modulePolicy, ExternalMethodTaintPolicy, externalMethodTaintPolicyDispatch, 
         externalMethodWrapperPolicyDispatch, ExternalMethodWrapPrePolicy, 
         WrapperPolicyType, ExternalMethodWrapPostPolicy } from './PolicyInterface';
import { State, taintEntry, ID, setMt, setPath, getTc } from '../State';
import { Wrapped, Unwrapped, unwrap, wrap } from '../Wrapper';
import { F, Either, NativeFunction, ExternalFunction } from '../Flib';
import { getTaintEntry, getValue, setPropTaint, getPropTaint, oid,
         initPropMap, isTainted, anyPropertiesTainted } from '../Taint';
import { SafeMap } from '../DataStructures';
import { newPathNode } from '../TaintPaths';
import { getObjectPolicy } from './PolicyManager';


export const MapPolicyImprecise: modulePolicy = {

    externalMethodWrapperPolicies: {},
    externalMethodTaintPolicies: {
        'set': mapSetImprecisePolicy,
        'get': mapGetImprecisePolicy,
    },

    // Not used
    isTainted(s: State, v: Wrapped) {
        const tE = F.eitherThrow(getTaintEntry(s, v));
        return tE.taintBit;
    },

    WrapPre(s: State, value: Unwrapped): [State, Wrapped] {
        // Unwrap the array elements
        let si = s;
        value.forEach(function(key: any, mapValue: any) {
            let [siP, unwrapped_elem_i] = F.eitherThrow(unwrap(si, mapValue));
            // Discard IDs
            var [siPP, _] = F.eitherThrow(wrap(siP, {}));
            value.set(key, unwrapped_elem_i);
            si = siPP;
        });
        return getObjectPolicy().WrapPre(s, value);
    },

    WGetField(s: State, r: Wrapped | Unwrapped): [State, Wrapped | Unwrapped] {
        return getObjectPolicy().WGetField(s, r);
    },

    WPutFieldPre(s: State, v: Wrapped): [State, Wrapped | Unwrapped] {
        return getObjectPolicy().WPutFieldPre(s, v);
    },

    WPutField(s: State, u: Unwrapped): [State, Wrapped | Unwrapped] {
        return getObjectPolicy().WPutField(s, u);
    },

    WInvokeFunPre(s: State, f: Wrapped, base: Wrapped, args: Wrapped[]): [State, any, any[]] {
        return getObjectPolicy().WInvokeFunPre(s, f, base, args);
    },

    WInvokeFun(s: State, f: any, base: any, args: any[], result: any): [State, any, any[], any] {
        return getObjectPolicy().WInvokeFun(s, f, base, args, result);
    },

    TGetField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        return getObjectPolicy().TGetField(s, v1, v2, v3);
    },
    
    TPutField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        return getObjectPolicy().TPutField(s, v1, v2, v3);
    },

    TBinary(s: State, op: string, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        return getObjectPolicy().TBinary(s, op, v1, v2, v3);
    },

    TUnary(s: State, v1: Object, v2: Object): Either<State, Error> {
        return getObjectPolicy().TUnary(s, v1, v2);
    },

    TCall(
        s: State, 
        f: ExternalFunction, 
        base: Wrapped, 
        args: Wrapped[], 
        result: Wrapped
    ): Either<State, Error> {
        F.assert(getValue(s, base) instanceof Map, `Base ${base} is not an map`);
        return F.matchMaybe(externalMethodTaintPolicyDispatch(this.externalMethodTaintPolicies, f), {
            Just: (policy: ExternalMethodTaintPolicy) => policy(s, f as NativeFunction, base, args, result),
            // Fall back to Object policy
            Nothing: () => getObjectPolicy().TCall(s, f, base, args, result)
        });
    }
};


function mapSetImprecisePolicy(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {
    // Get info about existing state
    let baseTaint: taintEntry = F.eitherThrow(getTaintEntry(s, base));
    let someArgTainted = false;
    for (let i in args) {
        F.matchEither(getTaintEntry(s, args[i]), {
            Left: (tE: taintEntry) => {
                someArgTainted = someArgTainted || tE.taintBit;
            },
            Right: (_: Error) => {
                // Default to false
                someArgTainted = someArgTainted || false;
            }
        })
    }
    // Policy: b or c Tainted ==> a Tainted in a.set(b, c)
    if (someArgTainted) {
        var baseTaintP: taintEntry = {
            taintBit: true,
            map: baseTaint.map,
            path: newPathNode(
                'model:map.set', [baseTaint.path], getValue(s, base), getTc(s)),
        };
    } else {
        var baseTaintP: taintEntry = baseTaint;
    }
    // Update state
    let resultState: State = s;
    let baseElemId: Object | ID = F.eitherThrow(oid(s, base));
    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(baseElemId, baseTaintP);
    let finalState: State = setMt(resultState, newMt);
    return F.Left(finalState);
}


function mapGetImprecisePolicy(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {
    // Get info about existing state
    let baseTaint: taintEntry = F.eitherThrow(getTaintEntry(s, base));
    let resultTaint: taintEntry = F.eitherThrow(getTaintEntry(s, result));
    let resultVal: any = result as any;

    // Policy a T => a.get(b) T
    let taintBitP: boolean = resultTaint.taintBit 
                || baseTaint.taintBit 
                || F.eitherThrow(anyPropertiesTainted(s, base));
    
    let resultTaintP: taintEntry = {
        taintBit: taintBitP,
        map: initPropMap(resultVal, taintBitP),
        path: newPathNode(
            'model:map.get', [baseTaint.path], getValue(s, resultVal), getTc(s)),
    }
    
    // Update state
    let resultState: State = s;
    let resultElemId: Object | ID = F.eitherThrow(oid(s, result));
    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultElemId, resultTaintP);
    let finalState: State = setMt(resultState, newMt);
    return F.Left(finalState);
}


export const MapPolicyPrecise: modulePolicy = {

    externalMethodWrapperPolicies: {
        'set': {
            pre: F.Just(setWrapPre),
            post: F.Nothing(),
        },
    },

    externalMethodTaintPolicies: {
        'set': mapSetPrecisePolicy,
        'get': mapGetPrecisePolicy,
    },

    // Not used
    isTainted(s: State, v: Wrapped) {
        const tE = F.eitherThrow(getTaintEntry(s, v));
        return tE.taintBit;
    },

    WrapPre(s: State, value: Unwrapped): [State, Wrapped] {
        // Wrap the map elements
        let si = s;
        value.forEach(function(key, mapValue) {
            let [siP, wrapped_elem_i] = F.eitherThrow(wrap(si, mapValue));
            value.set(key, wrapped_elem_i);
            si = siP;
        });
        return [si, value];
    },

    WGetField(s: State, r: Wrapped | Unwrapped): [State, Wrapped | Unwrapped] {
        return getObjectPolicy().WGetField(s, r);
    },

    WPutFieldPre(s: State, v: Wrapped): [State, Wrapped | Unwrapped] {
        return getObjectPolicy().WPutFieldPre(s, v);
    },

    WPutField(s: State, u: Unwrapped): [State, Wrapped | Unwrapped] {
        return getObjectPolicy().WPutField(s, u);
    },

    WInvokeFunPre(s: State, f: Wrapped, base: Wrapped, args: Wrapped[]): [State, any, any[]] {
        return F.matchMaybe(externalMethodWrapperPolicyDispatch(this.externalMethodWrapperPolicies, f as Function, WrapperPolicyType.pre), {
            Just: (policy: ExternalMethodWrapPrePolicy) => F.eitherThrow(policy(s, f as Function, base, args)),
            // Fall back to Object policy
            Nothing: () => getObjectPolicy().WInvokeFunPre(s, f, base, args),
        });
    },

    WInvokeFun(s: State, f: any, base: any, args: any[], result: any): [State, any, any[], any] {
        return F.matchMaybe(externalMethodWrapperPolicyDispatch(this.externalMethodWrapperPolicies, f, WrapperPolicyType.post), {
            Just: (policy: ExternalMethodWrapPostPolicy) => F.eitherThrow(policy(s, f, base, args, result)),
            // Fall back to Object policy
            Nothing: () => getObjectPolicy().WInvokeFun(s, f, base, args, result),
        });
    },

    TGetField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        return getObjectPolicy().TGetField(s, v1, v2, v3);
    },
    
    TPutField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        return getObjectPolicy().TPutField(s, v1, v2, v3);
    },

    TBinary(s: State, op: string, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        return getObjectPolicy().TBinary(s, op, v1, v2, v3);
    },

    TUnary(s: State, v1: Object, v2: Object): Either<State, Error> {
        return getObjectPolicy().TUnary(s, v1, v2);
    },

    TCall(
        s: State, 
        f: ExternalFunction, 
        base: Wrapped, 
        args: Wrapped[], 
        result: Wrapped
    ): Either<State, Error> {
        F.assert(getValue(s, base) instanceof Map, `Base ${base} is not an map`);
        return F.matchMaybe(externalMethodTaintPolicyDispatch(this.externalMethodTaintPolicies, f), {
            Just: (policy: ExternalMethodTaintPolicy) => policy(s, f as NativeFunction, base, args, result),
            // Fall back to Object policy
            Nothing: () => getObjectPolicy().TCall(s, f, base, args, result)
        });
    }
};

function setWrapPre( 
    s: State,
    f: Function,
    base: Wrapped,
    args: Wrapped[],
): Either<[State, any, any[]], Error> {
    // Unwrap the first argument, but not the second
    let unwrapped_args = [];
    let [s1, unwrapped_key] = F.eitherThrow(unwrap(s, args[0]));
    // Discard IDs
    var [s2, _] = F.eitherThrow(wrap(s1, {}));
    unwrapped_args.push(unwrapped_key);
    unwrapped_args.push(args[1]);
    return F.Left([s2, base, unwrapped_args]);
}

function mapSetPrecisePolicy(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {
    return F.Left(s);
}


function mapGetPrecisePolicy(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {
    return F.Left(s);
}

