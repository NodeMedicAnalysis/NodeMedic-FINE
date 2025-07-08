import { F, Either, Literal, Maybe, ExternalFunction } from './Flib';
import { State, ID, PropMap, taintEntry, setMt, setPath, getTc } from './State';
import { emptyPathNode, newPathNode, describePath, circularReplacer } from './TaintPaths';
import { Wrapped } from './Wrapper';
import { getPolicy, getCurrentContext } from './modules/PolicyManager';
import { TEvalPolicy, EvalApplyRewritePolicy } from './modules/Eval';
import { exec, execSync, spawn, spawnSync } from 'child_process';
import { SafeMap } from './DataStructures';
import { runInNewContext, runInThisContext, runInContext } from 'vm';

// Default sinks: new Function, exec, eval
// (eval is handled in modules/Eval.ts)
const _SINKS: ReadonlyArray<[Function, string]> = [
    [Function, 'Function'],
    [exec, 'exec'],
    [execSync, 'exec'],
    [eval, 'eval'],
    [runInNewContext, 'eval'],
    [runInThisContext, 'eval'],
    [runInContext, 'eval'],
    [spawn, 'spawn'],
    [spawnSync, 'spawn'],
];
export const CORE_SINKS: ReadonlyMap<Function, string> = new Map(_SINKS);
export const SINKS: SafeMap<Function, string> = new SafeMap(F.Just(new Map(_SINKS)));

export function oid(s: State, v: Object): Either<ID | Object, Error> {
    return F.matchMaybe(s.Mw.get(v), {
        Just: ([id, _]): Either<ID | Object, Error> => F.Left(id),
        // An object; we don't have an OID for it in Mw
        Nothing: (): Either<ID | Object, Error> => {
            if (F.isLiteral(v) && !F.isUndefinedOrNull(v)) {
                // return F.Right(Error(`Literal ${v.toString()} does not have an entry in the wrapper map`));
                return F.Left({});
            }
            return F.Left(v);
        }
    });
}

export function initPropMap(v: Object, taintBit: boolean): Maybe<PropMap> {
    // Invariant: Only strings have property maps
    if (F.isString(v)) {
        let propMap = new PropMap(v);
        if (taintBit) {
            let keys = propMap.keys();
            let propMapP = propMap;
            for(let i in keys) {
                propMapP = propMapP.set(keys[i], true);
            }
            return F.Just(propMapP);
        } else {
            return F.Just(propMap);
        }
    } else {
        return F.Nothing();
    }
}

export function getValue(s: State, v: Wrapped): Literal | Object {
    return F.matchMaybe(s.Mw.get(v), {
        Just: ([_, val]) => val,
        Nothing: () => v,
    });
}

function getTaintEntryWithID(s: State, v: Object, id: ID | Object): taintEntry {
    return F.matchMaybe(s.Mt.get(id), {
        Just: (tE: taintEntry): taintEntry => tE,
        Nothing: (): taintEntry => {
            return {
                taintBit: false,
                map: initPropMap(getValue(s, v), false),
                path: emptyPathNode(getValue(s, v), getTc(s)),
            };;
        },
    });
}

export function isTainted(s: State, v: Wrapped): Either<boolean, Error> {
    let tE: taintEntry = F.eitherThrow(getTaintEntry(s, v));
    return F.Left(tE.taintBit || F.eitherThrow(anyPropertiesTainted(s, v)));
}

export function getTaintEntry(s: State, v: Object): Either<taintEntry, Error> {
    return F.matchEither(oid(s, v), {
        Left: (id: ID | Object) => F.Left(getTaintEntryWithID(s, v, id)),
        Right: (err: Error) => F.Right(err)
    });
}

export function anyPropertiesTainted(s: State, v: Wrapped): Either<boolean, Error> {
    let tE = F.eitherThrow(getTaintEntry(s, v));
    return F.matchMaybe(tE.map, {
        Just: (x: PropMap): Either<boolean, Error> => {
            // v is a string.
            F.assert(F.isString(v), `v was not a string`);
            let anyTainted = false;
            x.forEach(function(value, key) {
                anyTainted = anyTainted || value;
            });
            return F.Left(anyTainted);
        },
        Nothing: (): Either<boolean, Error> => {
            let anyTainted = false;
            if (Array.isArray(v)) {
                v.forEach((elem) => {
                    let tainted = F.isLiteral(elem) ?
                        false :
                        F.matchEither(getTaintEntry(s, elem), {
                            Left: (tE: taintEntry) => tE.taintBit,
                            Right: (_) => false
                        });
                    anyTainted = anyTainted || tainted;
                });
            } else if (!F.isUndefinedOrNull(v)) {
                Object.getOwnPropertyNames(v).forEach(function(propName) {
                    const propDesc = Object.getOwnPropertyDescriptor(v, propName);
                    // Avoid properties that do not have a descriptor or are getters / setters
                    if (propDesc !== undefined 
                        && 'value' in propDesc 
                        && ['caller', 'callee', 'arguments'].indexOf(propName) == -1
                    ) {
                        let vi = v[propName];
                        let vi_tainted: boolean = F.matchEither(getTaintEntry(s, vi), {
                            Left: (tE: taintEntry) => tE.taintBit,
                            Right: (_) => false
                        });
                        anyTainted = anyTainted || vi_tainted;
                    }
                });
            }
            return F.Left(anyTainted);
        }
    });
}

export function allPropertiesTainted(s: State, v: Wrapped): Either<boolean, Error> {
    let tE = F.eitherThrow(getTaintEntry(s, v));
    return F.matchMaybe(tE.map, {
        Just: (x: PropMap): Either<boolean, Error> => {
            // v is a string.
            F.assert(F.isString(v), `v was not a string`);
            // An empty prop map should not count as tainted
            let allTainted = x.keys().length > 0;
            x.forEach(function(value, key) {
                allTainted = allTainted && value;
            });
            return F.Left(allTainted);
        },
        Nothing: (): Either<boolean, Error> => {
            let allTainted = false;
            if (Array.isArray(v)) {
                // An array with no elements should not be tainted
                allTainted = v.length > 0;
                v.forEach((elem) => {
                    let tainted = F.isLiteral(elem) ?
                        false :
                        F.matchEither(getTaintEntry(s, elem), {
                            Left: (tE: taintEntry) => tE.taintBit,
                            Right: (_) => false
                        });
                    allTainted = allTainted && tainted;
                });
            } else {
                // A object with no properties should not be tainted
                allTainted = Object.getOwnPropertyNames(v).length > 0;
                Object.getOwnPropertyNames(v).forEach(function(propName) {
                    const propDesc = Object.getOwnPropertyDescriptor(v, propName);
                    // Avoid properties that do not have a descriptor or are getters / setters
                    if (propDesc !== undefined 
                        && 'value' in propDesc 
                        && ['caller', 'callee', 'arguments'].indexOf(propName) == -1
                    ) {
                        let vi = v[propName];
                        let vi_tainted: boolean = F.matchEither(getTaintEntry(s, vi), {
                            Left: (tE: taintEntry) => tE.taintBit,
                            Right: (_) => false
                        });
                        allTainted = allTainted && vi_tainted;
                    }
                });
            }
            return F.Left(allTainted);
        }
    });
}

export function TSet(s: State, v: Object, b: boolean): Either<State, Error> {
    let id = F.eitherThrow(oid(s, v));
    return F.matchEither(getTaintEntry(s, v), {
        Left: (entry: taintEntry) => {
            let MtP = s.Mt.set(id, {
                taintBit: b,
                map: initPropMap(v, b),
                path: newPathNode(
                    'Tainted', 
                    [entry.path],
                    getValue(s, v),
                    getTc(s)
                ),
            });
            let sP = setMt(s, MtP);
            return F.Left(sP);
        },
        Right: (_) => {
            let MtP = s.Mt.set(id, {
                taintBit: b,
                map: initPropMap(v, b),
                path: newPathNode(
                    'Tainted', 
                    [emptyPathNode(getValue(s, v), getTc(s))], 
                    getValue(s, v),
                    getTc(s)
                ),
            });
            let sP = setMt(s, MtP);
            return F.Left(sP);
        }
    });
}

// This should only be called by the ghost function __jalangi_set_prop_taint__
export function TSetProp(s: State, v: Object, p: string, b: boolean): Either<State, Error> {
    if (!F.isString(v)) {
        return F.Right(Error(`Tried to set property taint on non-string: ${v}`))
    }
    let id = F.eitherThrow(oid(s, v));
    let tE = getTaintEntryWithID(s, v, id);
    let propMap: PropMap = F.matchMaybe(tE.map, {
        Just: (m: PropMap): PropMap => m,
        Nothing: () => new PropMap(v),
    });
    propMap = propMap.set(p, b);
    // If any character of the string is tainted then
    // the length should be tainted as well
    propMap = propMap.set('length', true);
    let tEP: taintEntry = {
        taintBit: F.eitherThrow(allPropertiesTainted(s, v)),
        map: F.Just(propMap),
        path: newPathNode('Tainted', [tE.path], getValue(s, v), getTc(s)),
    };
    let MtP = s.Mt.set(id, tEP);
    let sP = setMt(s, MtP);
    return F.Left(sP);
}

export function TGetTaintAll(s: State, v: Object): Either<boolean, Error> {
    let tE = F.eitherThrow(getTaintEntry(s, v));
    // TODO Object.getOwnPropertyNames(v: Wrapped) == Object.getOwnPropertyNames(unwrap(v))?
    if (v === undefined || Object.getOwnPropertyNames(v).length == 0) {
        // False positive: An object with no properties should not be tainted.
        return F.Left(tE.taintBit);
    } else {
        let allTainted = F.eitherThrow(allPropertiesTainted(s, v));
        return F.Left(tE.taintBit || allTainted);
    }   
}

export function TGetTaintAny(s: State, v: Object): Either<boolean, Error> {
    let tE = F.eitherThrow(getTaintEntry(s, v));
    // TODO Object.getOwnPropertyNames(v: Wrapped) == Object.getOwnPropertyNames(unwrap(v))?
    if (v === undefined || Object.getOwnPropertyNames(v).length == 0) {
        // False positive: An object with no properties should not be tainted.
        return F.Left(tE.taintBit);
    } else {
        let anyTainted = F.eitherThrow(anyPropertiesTainted(s, v));
        return F.Left(tE.taintBit || anyTainted);
    }
}

export function TCheck(s: State, v: Object) {
    let tainted = F.eitherThrow(TGetTaintAny(s, v));
    if (tainted) {
        describePath(F.eitherThrow(getTaintEntry(s, v)).path);
        setTimeout(() => {
            throw Error("Tainted argument found");
        });
        throw Error("Tainted argument found");
    }
}

export function TGetPropTaint(s: State, v: Object, property: string): Either<boolean, Error> {
    let id = F.eitherThrow(oid(s, v));
    let tE = getTaintEntryWithID(s, v, id);
    return F.matchMaybe(tE.map, {
        Just: (map: PropMap): Either<boolean, Error> => 
            F.matchMaybe(map.get(property), {
                Just: (taint: boolean) => F.Left(taint),
                Nothing: () => F.Right(Error(`PropMap does not have property: ${property}`)),
            }),
        Nothing: (): Either<boolean, Error> =>
            F.Right(Error(`TaintEntry does not have a PropMap; object: ${v}, id: ${id}`)),
    });
}

/** 
 * Get the taint of a property given a `taintEntry`.
 * 
 * If the `PropMap` does not exist or if `prop` does not exist in the map, 
 * default to returning the `taintBit`.
 * 
 * @param tE `taintEntry`
 * @param prop A property in the `PropMap`
 * @returns The taint of the property
 */
export function getPropTaint(tE: taintEntry, prop: string): boolean {
    return F.matchMaybe(tE.map, {
        Just: (map: PropMap) => {
            let propTaint = F.matchMaybe(map.get(prop), {
                Just: (taint) => taint,
                Nothing: () => false,
            });
            return tE.taintBit || propTaint;
        },
        Nothing: () => tE.taintBit,
    });
}

/** 
 * Sets the taint of a property for a `taintEntry`.
 * 
 * Preserves the invariant any key tainted => tainted string length.
 * *Throws an error if the `PropMap` does exist on the `taintEntry`.*
 * 
 * @param tE `taintEntry`
 * @param prop A property in the `PropMap`
 * @param value The taint of the property
 * @returns The updated `taintEntry`
 */
export function setPropTaint(tE: taintEntry, prop: string, value: boolean): taintEntry {
    return F.matchMaybe(tE.map, {
        Just: (map: PropMap) => {
            if (value) {
                let mapP0 = map.set(prop, value);
                // Preserve invariant: any key tainted => tainted string length
                var mapP = F.Just(mapP0.set('length', value));
            } else {
                var mapP = F.Just(map.set(prop, value));
            }
            let tEp: taintEntry = {
                taintBit: tE.taintBit,
                map: mapP,
                path: tE.path,
            };
            return tEp;
        },
        Nothing: () => {
            throw Error(`taintEntry does not have a map`);
        },
    });
}

export function TGetField(s: State, v1: Object, v2: Object, v3: Object): Either<State, Error> {
    let u1 = getValue(s, v1);
    return getPolicy(u1).TGetField(s, v1, v2, v3);
}

export function TPutField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
    let u1 = getValue(s, v1);
    return getPolicy(u1).TPutField(s, v1, v2, v3);
}

export function TBinary(s: State, op: string, v1: Object, v2: Object, v3: Object): Either<State, Error> {
    let u3 = getValue(s, v3);
    return getPolicy(u3).TBinary(s, op, v1, v2, v3);
}

export function TUnary(s: State, v1: Object, v2: Object): Either<State, Error> {
    let u1 = getValue(s, v1);
    return getPolicy(u1).TUnary(s, v1, v2);
}

export function TCall(
    s: State,
    f: ExternalFunction, 
    base: Object, 
    args: Object[], 
    result: Object, 
    isExternal: boolean
): Either<State, Error> {
    // We only propagate taint via policies for native fns with a result
    if (isExternal && result !== undefined) {
        let ubase = getValue(s, base);
        return getPolicy(ubase).TCall(s, f, base, args, result);
    } else {
        return F.Left(s);
    }
}

// rewrites the code that is being instrumented if needed, otherwise just re
export function TEvalPre(s: State, code: string, w: Wrapped): Either<[State, [string]], Error> {
    return EvalApplyRewritePolicy(s, code, w);
}

export function TCallPre(s: State, f: Wrapped, base: Wrapped, args: Array<Wrapped>): Either<State, Error> {
    let fP: Function = getValue(s, f) as Function;
    let baseP: Object = getValue(s, base) as Object;

    let cF = fP;
    if (fP === Function.prototype.apply || fP === Function.prototype.call) {
        cF = base as Function;
    }
    
    let Mti = s.Mt;
    for (let i in args) {
        let argID = F.eitherThrow(oid(s, args[i]));
        let argTE = F.eitherThrow(getTaintEntry(s, args[i]));
        let argTEP = setPath(
            argTE,
            newPathNode(
                `call:${F.getFunctionName(cF)}`, 
                [argTE.path], 
                getValue(s, args[i]),
                getTc(s),
                F.maybeToNullable(SINKS.get(cF))
            )
        );
        Mti = Mti.set(argID, argTEP);
    }
    let sP = setMt(s, Mti);

    return hitFuncSink(sP, fP, baseP, args);
}


export function TEval(s: State, code: Wrapped): Either<State, Error> {
    return TEvalPolicy(s, code);
}


export function TWrite(s: State, valP: Wrapped): Either<State, Error> {
    return getCurrentContext().TWrite(s, valP);
}

/** Asserts that the function sink has been hit with a tainted argument
 * 
 * @param s current state
 * @param x function (wrapped)
 * @param args the wrapped arguments passed ot the function
 */
export function hitFuncSink(s: State, x: Wrapped, base: Wrapped, args: Array<Wrapped>): Either<State, Error> {
    // TODO: more complicated policies, e.g. idx for which argument is tainted is specified in the policy
    let hasTaintedArg: boolean = false;
    let xP = getValue(s, x);
    
    let taintedIdx = [];
    for (let i = 0; i < args.length; i++) {
        try {
            let tE: taintEntry = F.eitherThrow(getTaintEntry(s, args[i]));
            if (tE.taintBit || F.eitherThrow(anyPropertiesTainted(s, args[i]))) {
                hasTaintedArg = true;
                taintedIdx.push(i);
            }
        } catch {
            // args have not been wrapped yet, so they aren't tainted, so we can ignore
        }
    }

    // Get the called function
    let cF = xP;
    if (xP === Function.prototype.apply || xP === Function.prototype.call) {
        cF = base;
    }

    if (hasTaintedArg) {
        SINKS.forEach((_, f: Function) => {
            if (f === cF) {
                for (let i in taintedIdx) {
                    describePath(F.eitherThrow(getTaintEntry(s, args[taintedIdx[i]])).path, i);
                }
                setTimeout(() => {
                    throw Error(`Sink ${f} reached with tainted arguments ${argsToString(args, (x) => taintedIdx.includes(x))}\n`);
                });
                throw Error(`Sink ${f} reached with tainted arguments ${argsToString(args, (x) => taintedIdx.includes(x))}\n`);
            }
        });
    }
    return F.Left(s);
}


/** Adds the function as a sink in our infrastructure
 * 
 * @param x 
 */
export function addFuncSink(x: Function, typ: string) {
    SINKS.set(x, typ);
}

function argsToString(arg: any, filter: Function) {
    if (Array.isArray(arg)) {
        let acc = '';
        for (let i = 0; i < arg.length; i++) {
            if (filter(i)) {
                acc += argsToString(arg[i], (x) => true);
                if (i != arg.length - 1) {
                    acc += ', ';
                }
            }
        }
        let outStr = `[${acc}]`;
        return outStr;
    } else {
        return JSON.stringify(arg, circularReplacer());
    }
}
