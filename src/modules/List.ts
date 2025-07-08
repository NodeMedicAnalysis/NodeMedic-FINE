import { modulePolicy, externalMethodTaintPolicyDispatch, ExternalMethodTaintPolicy } from './PolicyInterface';
import { State, taintEntry, ID, setMt, setPath, getTc } from '../State';
import { Wrapped, Unwrapped, unwrap, wrap } from '../Wrapper';
import { F, Either, NativeFunction, ExternalFunction } from '../Flib';
import { getTaintEntry, getValue, setPropTaint, getPropTaint, oid,
         initPropMap, isTainted, anyPropertiesTainted } from '../Taint';
import { SafeMap } from '../DataStructures';
import { newPathNode, joinTEPaths } from '../TaintPaths';
import { getObjectPolicy } from './PolicyManager';


export const ListPolicyImprecise: modulePolicy = {

    externalMethodWrapperPolicies: {},
    externalMethodTaintPolicies: {
        'push': arrayPush,
    },

    // Not used
    isTainted(s: State, v: Wrapped) {
        const tE = F.eitherThrow(getTaintEntry(s, v));
        return tE.taintBit;
    },

    WrapPre(s: State, value: Unwrapped): [State, Wrapped] {
        // Unwrap the array elements
        let si = s;
        for (let i = 0; i < value.length; i++) {
            let [siP, unwrapped_elem_i] = F.eitherThrow(unwrap(si, value[i]));
            // Discard IDs
            var [siPP, _] = F.eitherThrow(wrap(siP, {}));
            value[i] = unwrapped_elem_i;
            si = siPP;
        }
        return getObjectPolicy().WrapPre(s, value);
    },

    WGetField(s: State, r: Wrapped | Unwrapped): [State, Wrapped | Unwrapped] {
        return getObjectPolicy().WGetField(s, r);
    },

    WPutFieldPre(s: State, v: Wrapped): [State, Wrapped | Unwrapped] {
        let [sP, u] = F.eitherThrow(unwrap(s, v));
        return [sP, u];
    },

    WPutField(s: State, u: Unwrapped): [State, Wrapped | Unwrapped] {
        let [sP, v] = F.eitherThrow(wrap(s, u));
        return [sP, v];
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
        F.assert(getValue(s, base) instanceof Array, `Base ${base} is not an array`);
        return F.matchMaybe(externalMethodTaintPolicyDispatch(this.externalMethodTaintPolicies, f), {
            Just: (policy: ExternalMethodTaintPolicy) => policy(s, f as NativeFunction, base, args, result),
            // Fall back to Object policy
            Nothing: () => getObjectPolicy().TCall(s, f, base, args, result)
        });
    }
};

export const ListPolicyPrecise: modulePolicy = {

    externalMethodWrapperPolicies: {},
    externalMethodTaintPolicies: {
        'join': arrayJoin,
        'map': arrayMap,
        'reduce': arrayReduce,
        'reduceRight': arrayReduce,
    },

    // Not used
    isTainted(s: State, v: Wrapped) {
        const tE = F.eitherThrow(getTaintEntry(s, v));
        return tE.taintBit;
    },

    WrapPre(s: State, value: Unwrapped): [State, Wrapped] {
        // Wrap the array elements
        let si = s;
        for (let i = 0; i < value.length; i++) {
            let [siP, wrapped_elem_i] = F.eitherThrow(wrap(si, value[i]));
            value[i] = wrapped_elem_i;
            si = siP;
        }
        return [si, value];
    },

    WGetField(s: State, r: Wrapped | Unwrapped): [State, Wrapped | Unwrapped] {
        return ListPolicyImprecise.WGetField(s, r);
    },

    WPutFieldPre(s: State, v: Wrapped): [State, Wrapped | Unwrapped] {
        return [s, v];
    },

    WPutField(s: State, u: Unwrapped): [State, Wrapped | Unwrapped] {
        return [s, u];
    },

    WInvokeFunPre(s: State, f: Wrapped, base: Wrapped, args: Wrapped[]): [State, any, any[]] {
        return [s, base, args];
    },

    WInvokeFun(s: State, f: any, base: any, args: any[], result: any): [State, any, any[], any] {
        return [s, base, args, result];
    },

    TGetField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        return ListPolicyImprecise.TGetField(s, v1, v2, v3);
    },
    
    TPutField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        return ListPolicyImprecise.TPutField(s, v1, v2, v3);
    },

    TBinary(s: State, op: string, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        return ListPolicyImprecise.TBinary(s, op, v1, v2, v3);
    },

    TUnary(s: State, v1: Object, v2: Object): Either<State, Error> {
        return ListPolicyImprecise.TUnary(s, v1, v2);
    },

    TCall(
        s: State, 
        f: ExternalFunction, 
        base: Wrapped, 
        args: Wrapped[], 
        result: Wrapped
    ): Either<State, Error> {
        return F.matchMaybe(externalMethodTaintPolicyDispatch(this.externalMethodTaintPolicies, f), {
            Just: (policy: ExternalMethodTaintPolicy) => policy(s, f as NativeFunction, base, args, result),
            // Fall back to Object policy
            Nothing: () => getObjectPolicy().TCall(s, f, base, args, result)
        });
    },
};

function arrayPush(s: State,
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
    // Policy: b Tainted ==> a Tainted in a.push(b)
    if (someArgTainted) {
        var baseTaintP: taintEntry = {
            taintBit: true,
            map: baseTaint.map,
            path: newPathNode(
                'model:array.push', [baseTaint.path], getValue(s, base), getTc(s)),
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

// arr.join([separator])
function arrayJoin(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {

    if (args.length > 1) {
        throw Error("arrayJoin only supported for 0 or 1 args");
    }

    // Get info about existing state
    let resultState: State = s;
    let resultTaint: taintEntry = F.eitherThrow(getTaintEntry(s, result));

    // Taint updating logic
    if (args.length > 1) {
        throw Error("stringJoin taint policy only supported for zero or one args");
    }

    let baseVal: Array<any> = base as Array<any>;
    let delimiter: string = ",";
    if (args.length == 1) {
        delimiter = args[0].toString();
    }

    // For each element in base, add the corresponding taint bits then a untainted delimiter
    let inTEs: taintEntry[] = [];
    let offset: number = 0;
    for (var i = 0; i < baseVal.length; i++) {
        let argTE: taintEntry = F.eitherThrow(getTaintEntry(s, baseVal[i]));
        inTEs.push(argTE);
        let argVal = getValue(s, baseVal[i]).toString();
        if (F.isString(getValue(s, baseVal[i]))) {
            for (var j = 0; j < argVal.length; j++) {
                let tEVal: boolean = getPropTaint(argTE, j.toString());
                resultTaint = setPropTaint(resultTaint, (offset + j).toString(), tEVal);
            }
        } else {
            for (var j = 0; j < argVal.length; j++) {
                let tEVal: boolean = argTE.taintBit;
                resultTaint = setPropTaint(resultTaint, (offset + j).toString(), tEVal);
            }
        }

        // Delimiter should not be tainted as it is inserted by this function
        // Delimiter can be of variable length
        for (var delimiter_idx = 0; delimiter_idx < delimiter.length; delimiter_idx++) {
            resultTaint = 
                setPropTaint(resultTaint, (offset + argVal.length + delimiter_idx).toString(), false);
        }
        offset = offset + argVal.length + delimiter.length; 
    }

    let resultTaintP = setPath(
        resultTaint,
        newPathNode('model:array.join', joinTEPaths(inTEs), getValue(s, result), getTc(s))
    );
    
    // Update state
    let resultElemId: Object | ID = F.eitherThrow(oid(s, result));
    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultElemId, resultTaintP);
    let finalState: State = setMt(resultState, newMt);
    return F.Left(finalState);
}

function arrayMap(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {
    F.assert(
        (base as Array<any>).length == (result as Array<any>).length,
        'Base and result must have the same length'
    );
    // arr.map(f) := [f(x) for x in arr]
    // Policy: for f(x) in arr.map(f) where f(x) untainted:
    //              x tainted in arr \/ arr tainted ==> f(x) tainted
    let baseVal = base as Array<any>;
    let resultVal = result as Array<any>;
    let si: State = s;
    for (let i in baseVal) {
        let resultElem = resultVal[i];
        // We only apply this policy when we can make the result more precise
        // e.g., in the case where f is really Native or External
        let resultElemTE = F.eitherThrow(getTaintEntry(s, resultElem));
        let imprecise = 
               resultElemTE.path != undefined 
            && resultElemTE.path.parents != undefined 
            && resultElemTE.path.parents.size == 0;
        if (imprecise) {
            let baseTE: taintEntry = F.eitherThrow(getTaintEntry(s, base));
            let elemTE: taintEntry = F.eitherThrow(getTaintEntry(s, baseVal[i]));
            let tainted: boolean = baseTE.taintBit || F.eitherThrow(isTainted(s, baseVal[i]));
            let resultElemID: Object | ID = F.eitherThrow(oid(s, resultElem))
            let resultElemTEp: taintEntry = {
                taintBit: tainted,
                map: initPropMap(resultElem, tainted),
                path: newPathNode(
                    'model:array.map', [elemTE.path], getValue(s, resultElem), getTc(s)),
            }
            let MtP = si.Mt.set(resultElemID, resultElemTEp);
            let siP = setMt(si, MtP);
            si = siP;
        }
    }
    return F.Left(si);
}

function arrayReduce(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {
    // arr.reduce(f) := r
    // Policy: arr tainted \/ x tainted in arr ==> r tainted
    let baseVal = base as Array<any>;
    let resultVal = result as any;
    let resultValTE = F.eitherThrow(getTaintEntry(s, resultVal));
    let imprecise = 
        resultValTE.path != undefined 
        && resultValTE.path.parents != undefined 
        && resultValTE.path.parents.size == 0
        && !F.eitherThrow(anyPropertiesTainted(s, resultVal));
    if (imprecise) {
        let baseTE: taintEntry = F.eitherThrow(getTaintEntry(s, base));
        let pathNodes = [];
        let tainted = baseTE.taintBit;
        for (let i in baseVal) {
            tainted = tainted || F.eitherThrow(isTainted(s, baseVal[i]));
            if (tainted) {
                let elemTE: taintEntry = F.eitherThrow(getTaintEntry(s, baseVal[i]));
                pathNodes.push(elemTE);
            }
        }
        let resultValID: Object | ID = F.eitherThrow(oid(s, resultVal))
        let resultValTEp: taintEntry = {
            taintBit: tainted,
            map: initPropMap(resultVal, tainted),
            path: newPathNode(
                'model:array.reduce', 
                joinTEPaths(pathNodes), getValue(s, resultVal), getTc(s)),
        }
        let MtP = s.Mt.set(resultValID, resultValTEp);
        let sP = setMt(s, MtP);
        return F.Left(sP);
    }
    return F.Left(s);
}
