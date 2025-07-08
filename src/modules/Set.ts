import { modulePolicy, ExternalMethodTaintPolicy, externalMethodTaintPolicyDispatch, 
         externalMethodWrapperPolicyDispatch, ExternalMethodWrapPrePolicy, 
         WrapperPolicyType, ExternalMethodWrapPostPolicy } from './PolicyInterface';
import { State, taintEntry, ID, setMt, setPath, getTc } from '../State';
import { Wrapped, Unwrapped, unwrap, wrap } from '../Wrapper';
import { F, Either, NativeFunction, ExternalFunction } from '../Flib';
import { getTaintEntry, getValue, setPropTaint, getPropTaint, oid,
         initPropMap, isTainted, anyPropertiesTainted } from '../Taint';
import { SafeMap } from '../DataStructures';
import { newPathNode, joinTEPaths } from '../TaintPaths';
import { getObjectPolicy } from './PolicyManager';


export const SetPolicyImprecise: modulePolicy = {

    externalMethodWrapperPolicies: {},
    externalMethodTaintPolicies: {
        'add': setAddImprecisePolicy,
        'values': setValuesImprecisePolicy,
    },
    
    // Not used
    isTainted(s: State, v: Wrapped) {
        const tE = F.eitherThrow(getTaintEntry(s, v));
        return tE.taintBit;
    },

    WrapPre(s: State, value: Unwrapped): [State, Wrapped] {
        // Unwrap the set elements
        let si = s;
        let unwrapped_values = [];
        value.forEach(function(setValue) {
            let [siP, unwrapped_elem_i] = F.eitherThrow(unwrap(si, setValue));
            // Discard IDs
            var [siPP, _] = F.eitherThrow(wrap(siP, {}));
            si = siPP;
            unwrapped_values.push(unwrapped_elem_i);
        });
        value.clear();
        for (let uSetValue of unwrapped_values) {
            value.add(uSetValue);
        }
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
        F.assert(getValue(s, base) instanceof Set, `Base ${base} is not an set`);
        return F.matchMaybe(externalMethodTaintPolicyDispatch(this.externalMethodTaintPolicies, f), {
            Just: (policy: ExternalMethodTaintPolicy) => policy(s, f as NativeFunction, base, args, result),
            // Fall back to Object policy
            Nothing: () => getObjectPolicy().TCall(s, f, base, args, result)
        });
    }
};


function setAddImprecisePolicy(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {
    // Get info about existing state
    let baseTaint: taintEntry = F.eitherThrow(getTaintEntry(s, base));
    let argTE: taintEntry =  F.eitherThrow(getTaintEntry(s, args[0])) ;
    // Policy: b Tainted ==> a Tainted in a.add(b)
    if (argTE.taintBit || anyPropertiesTainted(s, args[0])) {
        var baseTaintP: taintEntry = {
            taintBit: true,
            map: baseTaint.map,
            path: newPathNode(
                'model:set.add', [baseTaint.path], getValue(s, base), getTc(s)),
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


function setValuesImprecisePolicy(
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


export const SetPolicyPrecise: modulePolicy = {

    externalMethodWrapperPolicies: {
        'add': {
            pre: F.Just(addWrapPre),
            post: F.Nothing(),
        },
    },

    externalMethodTaintPolicies: {
        'add': setAddPrecisePolicy,
        'values': setValuesPrecisePolicy,
    },

    // Not used
    isTainted(s: State, v: Wrapped) {
        const tE = F.eitherThrow(getTaintEntry(s, v));
        return tE.taintBit;
    },

    WrapPre(s: State, value: Unwrapped): [State, Wrapped] {
        // Wrap the map elements
        let si = s;
        let wrapped_values = [];
        value.forEach(function(setValue) {
            let [siP, wrapped_elem_i] = F.eitherThrow(wrap(si, setValue));
            wrapped_values.push(wrapped_elem_i);
            si = siP;
        });
        value.clear();
        for (let wrapped_value of wrapped_values) {
            value.add(wrapped_value);
        }
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
        F.assert(getValue(s, base) instanceof Set, `Base ${base} is not an set`);
        return F.matchMaybe(externalMethodTaintPolicyDispatch(this.externalMethodTaintPolicies, f), {
            Just: (policy: ExternalMethodTaintPolicy) => policy(s, f as NativeFunction, base, args, result),
            // Fall back to Object policy
            Nothing: () => getObjectPolicy().TCall(s, f, base, args, result)
        });
    }
};

function addWrapPre( 
    s: State,
    f: Function,
    base: Wrapped,
    args: Wrapped[],
): Either<[State, any, any[]], Error> {
    return F.Left([s, base, args]);
}

function setAddPrecisePolicy(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {
    return F.Left(s);
}


function setValuesPrecisePolicy(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {
    return F.Left(s);
}

