import { modulePolicy, externalMethodWrapperPolicyDispatch, ExternalMethodWrapPrePolicy,
         ExternalMethodWrapPostPolicy, WrapperPolicyType } from './PolicyInterface';
import { State, taintEntry, ID, setMt, setIDS, taintTree, setTaintTreeMap, getTaintTreeMap, getTc } from '../State';
import { Wrapped, Unwrapped, unwrap, wrap, getID } from '../Wrapper';
import { F, Either, Maybe, NativeFunction, ExternalFunction } from '../Flib';
import { getTaintEntry, oid, initPropMap, allPropertiesTainted, getValue, anyPropertiesTainted } from '../Taint';
import { SafeMap } from '../DataStructures';
import { PathNode, newPathNode, joinTEPaths, describePath, emptyPathNode } from '../TaintPaths';


function unwrapObject(
    s: State, 
    value: Wrapped, 
    children: taintTree[],
    _visited?: Set<any>,
): Either<[State, Unwrapped], Error> {
    if (_visited === undefined) {
        _visited = new Set();
    }
    if (!F.isUndefinedOrNull(value) && typeof value == 'object') {
        let obj = value;
        Object.getOwnPropertyNames(obj).forEach(function(property: string) {
            let branch: taintTree = {property: property, id: F.Nothing(), children: []};
            let descriptor = Object.getOwnPropertyDescriptor(obj, property);
            const child = obj[property];
            if (descriptor.writable && !_visited.has(child)) {
                _visited.add(child);
                let [si, upi] = F.eitherThrow(unwrapObject(s, child, branch.children, _visited));
                let [_, id] = getID(si.frame.IDS);
                branch.id = F.Just(id);
                children.push(branch);
                obj[property] = upi;
            }
        });
    }
    let [sP, objP] = F.eitherThrow(unwrap(s, value));
    return F.Left([sP, objP]);
}


function wrapObject(
    s: State, 
    obj: Unwrapped,
    trees: taintTree[],
): Either<[State, Wrapped], Error> {
    let si = s;
    trees.forEach(function(branch: taintTree) {
        if (Object.hasOwnProperty.bind(obj)(branch.property)) {
            const propDesc = Object.getOwnPropertyDescriptor(obj, branch.property.toString());
            // Avoid properties that do not have a descriptor or are getters / setters
            if (propDesc !== undefined && 'value' in propDesc) {
                let IDSp = s.frame.IDS.push(F.maybeThrow(branch.id));
                let s1 = setIDS(si, IDSp);
                let [s2, propP] = F.eitherThrow(wrap(s1, obj[branch.property.toString()]));
                let [s3, propPP] = F.eitherThrow(wrapObject(s2, propP, branch.children));
                obj[branch.property.toString()] = propPP;
                si = s3;
            }
        }
    });
    return F.Left([si, obj]);
}


export const ObjectPolicy: modulePolicy = {

    externalMethodWrapperPolicies: {
        'defineProperty': {
            pre: F.Just(definePropertyWrapPre),
            post: F.Nothing(),
        },
    },

    externalMethodTaintPolicies: {},

    isTainted(s: State, v: Wrapped) {
        const tE = F.eitherThrow(getTaintEntry(s, v));
        return tE.taintBit;
    },

    WrapPre(s: State, value: Unwrapped): [State, Wrapped] {
        return [s, value];
    },

    WGetField(s: State, r: Wrapped): [State, Wrapped | Unwrapped] {
        let [sP, rP] = F.eitherThrow(wrap(s, r));
        return [sP, rP];
    },

    WPutFieldPre(s: State, v: Wrapped): [State, Wrapped | Unwrapped] {
        // We do not unwrap the value. This is necessary to preserve the value's taint.
        // This safe because getField will not wrap its result if it is already wrapped.
        return [s, v];
    },

    WPutField(s: State, u: Unwrapped): [State, Wrapped | Unwrapped] {
        return [s, u];
    },

    WInvokeFunPre(s: State, f: Function, base: Wrapped, args: Wrapped[]): [State, any, any[]] {
        return F.matchMaybe(externalMethodWrapperPolicyDispatch(this.externalMethodWrapperPolicies, f, WrapperPolicyType.pre), {
            Just: (policy: ExternalMethodWrapPrePolicy) => F.eitherThrow(policy(s, f, base, args)),
            // Fall back to ObjectPolicy
            Nothing: () => {
                // Unwrap the arguments
                let unwrapped_args = [];
                let si = s;
                let taintTrees = new WeakMap();
                for (let i in args) {
                    // let [siP, ui] = F.eitherThrow(unwrap(si, args[i]));
                    let trees: taintTree[] = [];
                    let [siP, ui] = F.eitherThrow(unwrapObject(si, args[i], trees));
                    // console.log(util.inspect(trees, false, 10));
                    if (trees.length > 0) {
                        taintTrees.set(ui, trees);
                    }
                    unwrapped_args.push(ui);
                    si = siP;
                }
                let siP: State = setTaintTreeMap(si, taintTrees);
                return [siP, base, unwrapped_args];
            }
        });
    },

    WInvokeFun(s: State, f: Function, base: any, args: any[], result: any): [State, any, any[], any] {
        return F.matchMaybe(externalMethodWrapperPolicyDispatch(this.externalMethodWrapperPolicies, f, WrapperPolicyType.post), {
            Just: (policy: ExternalMethodWrapPostPolicy) => F.eitherThrow(policy(s, f, base, args, result)),
            // Fall back to ObjectPolicy
            Nothing: () => {
                // Wrap the arguments
                let wrapped_args = [];
                let si = s;
                // Iterate through the arguments in reverse order
                for (let i = args.length - 1; i >= 0; i--) {
                    let argI: Unwrapped = args[i];
                    let taintTreeMap: WeakMap<object, taintTree[]> = getTaintTreeMap(s);
                    if (taintTreeMap.has(argI)) {
                        // console.log(util.inspect(taintTreeMap.get(argI), false, 10));
                        [si, argI] = F.eitherThrow(wrapObject(si, argI, taintTreeMap.get(argI)));
                    }
                    let [siP, wi] = F.eitherThrow(wrap(si, argI));
                    // Push it to the front of the arguments list
                    wrapped_args.unshift(wi);
                    si = siP;
                }
                return [si, base, wrapped_args, result];
            }
        });
    },

    TGetField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        let tE1: taintEntry = F.eitherThrow(getTaintEntry(s, v1));
        let tP2: PathNode = F.matchMaybe(s.Mt.get(F.eitherThrow(oid(s, v2))), {
            Just: (tE) => tE.path,
            Nothing: () => emptyPathNode(getValue(s, v2), getTc(s)),
        });
        let id3: ID | Object = F.eitherThrow(oid(s, v3));
        return F.matchMaybe(s.Mt.get(id3), {
            Just: (tE3: taintEntry): Either<State, Error> => {
                // If v3 already has a taintEntry, only override it if the taint of
                // tE1 is set.
                let MtP = s.Mt.set(id3, {
                    taintBit: this.isTainted(s, v1) || this.isTainted(s, v3),
                    map: tE3.map,
                    path: newPathNode(
                        'object.GetField', 
                        [tE1.path, tP2, tE3.path], getValue(s, v3), getTc(s)),
                });
                let sP = setMt(s, MtP);
                return F.Left(sP);
            },
            Nothing: (): Either<State, Error> => {
                let MtP = s.Mt.set(id3, {
                    taintBit: this.isTainted(s, v1),
                    map: initPropMap(v3, tE1.taintBit),
                    path: newPathNode(
                        'object.GetField', 
                        [tE1.path, tP2], getValue(s, v3), getTc(s)),
                });
                let sP = setMt(s, MtP);
                return F.Left(sP);
            }
        });
    },

    TPutField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        let u1 = getValue(s, v1);
        let u2 = getValue(s, v2);
        let tE3 = F.eitherThrow(getTaintEntry(s, v3));
        let v3tainted = tE3.taintBit || F.eitherThrow(anyPropertiesTainted(s, v3));
        if (v3tainted && !F.isUndefinedOrNull(u2)) {
            var pollution = false;
            // Case 1: Overwriting the prototype chain
            let prototypeAliases = ['prototype', '__proto__'];
            if (prototypeAliases.indexOf(u2.toString()) != -1) {
                pollution = true;
            }
            // Case 2: Setting a prototype property
            if (u1 == Object.prototype) {
                pollution = true;
            }
            if (pollution) {
                describePath(F.eitherThrow(getTaintEntry(s, v3)).path);
                throw Error(`Detected modification of prototype with tainted value: ${u2.toString()}`);
            }
        }
        return F.Left(s);
    },

    /**
     * 
     * The semantics behind this are as follows:
     *         Mt' := Mt, (oid Mw v3) -> ((Mt[(oid Mw v1)].t || Mt[(oid Mw v2)].t), {})
        --------------------------------------------------------------------------------------- (TBinOp)
        E, S, Mw, IDS, Mt |> TBinOp op v1 v2 v3     -->     E, S, Mw, IDS, Mt' |> ()
    * 
    */
    TBinary(s: State, op: string, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        let tE1: taintEntry = F.eitherThrow(getTaintEntry(s, v1));
        let tE2: taintEntry = F.eitherThrow(getTaintEntry(s, v2));
        let id3: ID | Object = F.eitherThrow(oid(s, v3));
        let taint = this.isTainted(s, v1) || this.isTainted(s, v2);
        let tE3: taintEntry =  {
            taintBit: taint,
            map: initPropMap(v3, taint),
            path: newPathNode(
                op, joinTEPaths([tE1, tE2]), getValue(s, v3), getTc(s)),
        };
        let MtP = s.Mt.set(id3, tE3);
        let resultState: State = setMt(s, MtP);
        return F.Left(resultState);
    },

    /** Implements the unary taint semantics
     * 
     *                   Mt' := Mt, (oid Mw v2) -> ((Mt[(oid Mw v1)].t), {})
        ---------------------------------------------------------------------------- (TUnary)
        E, S, Mw, IDS, Mt |> TUnary op v1 v2     -->     E, S, Mw, IDS, Mt' |> ()
    * 
    */
    TUnary(s: State, v1: Object, v2: Object): Either<State, Error> {
        let tE1: taintEntry = F.eitherThrow(getTaintEntry(s, v1));
        let id2: ID | Object = F.eitherThrow(oid(s, v2));
    
        let MtP = s.Mt.set(id2, {
            taintBit: this.isTainted(s, v1),
            map: initPropMap(v2, tE1.taintBit),
            path: newPathNode(
                'object.Unary', [tE1.path], getValue(s, v1), getTc(s))
        });
    
        let sP = setMt(s, MtP);
        return F.Left(sP);
    },

    TCall(
        s: State, 
        f: ExternalFunction, 
        base: Wrapped, 
        args: Wrapped[], 
        result: Wrapped
    ): Either<State, Error> {
        // Get the taint entries
        let argsTaint = [];
        for (let i in args) {
            argsTaint.push(F.eitherThrow(getTaintEntry(s, args[i])));
        }
        let resultTaint = F.eitherThrow(getTaintEntry(s, result));
        let baseTaint = F.eitherThrow(getTaintEntry(s, base));
        return imprecisePolicy(f, s, F.Just([base, baseTaint]), argsTaint, resultTaint, result, this.isTainted);
    }
};


export const ObjectPolicyImprecise: modulePolicy = {

    externalMethodWrapperPolicies: {
        'defineProperty': {
            pre: F.Just(definePropertyWrapPre),
            post: F.Nothing(),
        },
    },

    externalMethodTaintPolicies: {},

    isTainted(s: State, v: Wrapped) {
        const tE = F.eitherThrow(getTaintEntry(s, v));
        return tE.taintBit || F.eitherThrow(anyPropertiesTainted(s, v));
    },

    WrapPre(s: State, value: Unwrapped): [State, Wrapped] {
        return ObjectPolicy.WrapPre(s, value);
    },

    WGetField(s: State, r: Wrapped): [State, Wrapped | Unwrapped] {
        return ObjectPolicy.WGetField(s, r);
    },

    WPutFieldPre(s: State, v: Wrapped): [State, Wrapped | Unwrapped] {
        return ObjectPolicy.WPutFieldPre(s, v);
    },

    WPutField(s: State, u: Unwrapped): [State, Wrapped | Unwrapped] {
        return ObjectPolicy.WPutField(s, u);
    },

    WInvokeFunPre(s: State, f: Function, base: Wrapped, args: Wrapped[]): [State, any, any[]] {
        return ObjectPolicy.WInvokeFunPre(s, f, base, args);
    },

    WInvokeFun(s: State, f: Function, base: any, args: any[], result: any): [State, any, any[], any] {
        return ObjectPolicy.WInvokeFun(s, f, base, args, result);
    },

    TGetField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        let tE1: taintEntry = F.eitherThrow(getTaintEntry(s, v1));
        let tP2: PathNode = F.matchMaybe(s.Mt.get(F.eitherThrow(oid(s, v2))), {
            Just: (tE) => tE.path,
            Nothing: () => emptyPathNode(getValue(s, v2), getTc(s)),
        });
        let id3: ID | Object = F.eitherThrow(oid(s, v3));
        return F.matchMaybe(s.Mt.get(id3), {
            Just: (tE3: taintEntry): Either<State, Error> => {
                // If v3 already has a taintEntry, only override it if the taint of
                // tE1 is set.
                let MtP = s.Mt.set(id3, {
                    taintBit: this.isTainted(s, v1) || this.isTainted(s, v3),
                    map: tE3.map,
                    path: newPathNode(
                        'object.GetField', 
                        [tE1.path, tP2, tE3.path], getValue(s, v3), getTc(s)),
                });
                let sP = setMt(s, MtP);
                return F.Left(sP);
            },
            Nothing: (): Either<State, Error> => {
                let MtP = s.Mt.set(id3, {
                    taintBit: this.isTainted(s, v1),
                    map: initPropMap(v3, tE1.taintBit),
                    path: newPathNode(
                        'object.GetField',
                        [tE1.path, tP2], getValue(s, v3), getTc(s)),
                });
                let sP = setMt(s, MtP);
                return F.Left(sP);
            }
        });
    },

    TPutField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        let u1 = getValue(s, v1);
        let u2 = getValue(s, v2);
        let tE3 = F.eitherThrow(getTaintEntry(s, v3));
        let v3tainted = tE3.taintBit || F.eitherThrow(anyPropertiesTainted(s, v3));
        if (v3tainted && !F.isUndefinedOrNull(u2)) {
            var pollution = false;
            // Case 1: Overwriting the prototype chain
            let prototypeAliases = ['prototype', '__proto__'];
            if (prototypeAliases.indexOf(u2.toString()) != -1) {
                pollution = true;
            }
            // Case 2: Setting a prototype property
            if (u1 == Object.prototype) {
                pollution = true;
            }
            if (pollution) {
                describePath(F.eitherThrow(getTaintEntry(s, v3)).path);
                throw Error(`Detected modification of prototype with tainted value: ${u2.toString()}`);
            }
        }
        let id1: ID | Object = F.eitherThrow(oid(s, v1));
        let tE1 = F.eitherThrow(getTaintEntry(s, v1));
        let taint = this.isTainted(s, v1) || this.isTainted(s, v3);
        let MtP = s.Mt.set(id1, {
            taintBit: taint,
            map: initPropMap(getValue(s, v1), taint),
            path: newPathNode(
                'object.PutField', joinTEPaths([tE1, tE3]), getValue(s, v3), getTc(s)),
        });
        let sP = setMt(s, MtP);
        return F.Left(sP);
    },

    TBinary(s: State, op: string, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        let tE1: taintEntry = F.eitherThrow(getTaintEntry(s, v1));
        let tE2: taintEntry = F.eitherThrow(getTaintEntry(s, v2));
        let id3: ID | Object = F.eitherThrow(oid(s, v3));
        let taint = this.isTainted(s, v1) || this.isTainted(s, v2);
        let tE3: taintEntry =  {
            taintBit: taint,
            map: initPropMap(v3, taint),
            path: newPathNode(op, joinTEPaths([tE1, tE2]), getValue(s, v3), getTc(s)),
        };
        let MtP = s.Mt.set(id3, tE3);
        let resultState: State = setMt(s, MtP);
        return F.Left(resultState);
    },

    TUnary(s: State, v1: Object, v2: Object): Either<State, Error> {
        let tE1: taintEntry = F.eitherThrow(getTaintEntry(s, v1));
        let id2: ID | Object = F.eitherThrow(oid(s, v2));
    
        let MtP = s.Mt.set(id2, {
            taintBit: this.isTainted(s, v1),
            map: initPropMap(v2, tE1.taintBit),
            path: newPathNode('object.Unary', [tE1.path], getValue(s, v1), getTc(s))
        });
    
        let sP = setMt(s, MtP);
        return F.Left(sP);
    },

    TCall(
        s: State, 
        f: ExternalFunction, 
        base: Wrapped, 
        args: Wrapped[], 
        result: Wrapped
    ): Either<State, Error> {
        // Get the taint entries
        let argsTaint = [];
        for (let i in args) {
            argsTaint.push(F.eitherThrow(getTaintEntry(s, args[i])));
        }
        let resultTaint = F.eitherThrow(getTaintEntry(s, result));
        let baseTaint = F.eitherThrow(getTaintEntry(s, base));
        return imprecisePolicy(f, s, F.Just([base, baseTaint]), argsTaint, resultTaint, result, this.isTainted);
    }
};


export function imprecisePolicy(
    f: Function,
    s: State,
    baseTaint: Maybe<[Wrapped, taintEntry]>, 
    argsTaint: taintEntry[], 
    resultTaint: taintEntry,
    result: Wrapped,
    isTainted: (s: State, v: Wrapped) => boolean,
): Either<State, Error> {
    let fname = F.getFunctionName(f);
    return F.matchMaybe(baseTaint, {
        Just: ([base, tE]: [Wrapped, taintEntry]): Either<State, Error> => {
            let allTainted = F.eitherThrow(allPropertiesTainted(s, base));
            if (isTainted(s, base) || allTainted) {
                let resultTaintP: taintEntry = {
                    taintBit: true,
                    map: initPropMap(result, true),
                    path: newPathNode(
                        `imprecise:${fname}`, 
                        joinTEPaths([tE, ...argsTaint]), getValue(s, result), getTc(s)),
                };

                // Update state
                let resultState: State = s;
                let resultElemId: Object | ID = F.eitherThrow(oid(s, result));
                let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultElemId, resultTaintP);
                let finalState: State = setMt(resultState, newMt);
                return F.Left(finalState);
            } else {
                // base isn't tainted
                let someTainted: boolean = false;
                argsTaint.forEach(taintArg => {
                    someTainted = someTainted || taintArg.taintBit;
                })
                if (!someTainted) {
                    // arguments and base are not tainted, so nothing is tainted, so skip
                    return F.Left(s);
                } else {
                    // handle the case where arguments are tainted and base isn't tainted
                    let resultTaintP: taintEntry = {
                        taintBit: true,
                        map: initPropMap(result, true),
                        path: newPathNode(
                            `imprecise:${fname}`, 
                            joinTEPaths([tE, ...argsTaint]), 
                            getValue(s, result), getTc(s)),
                    };

                    // Update state
                    let resultState: State = s;
                    let resultElemId: Object | ID = F.eitherThrow(oid(s, result));
                    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultElemId, resultTaintP);
                    let finalState: State = setMt(resultState, newMt);
                    return F.Left(finalState);
                }
            }
        },
        Nothing: (): Either<State, Error> => {
            let someTainted = false;
            argsTaint.forEach(taintArg => {
                someTainted = someTainted || taintArg.taintBit;
            })
            if (!someTainted) {
                // arguments and base are not tainted, so nothing is tainted, so skip
                return F.Left(s);
            } else {
                // handle the case where arguments are tainted and base isn't tainted
                let resultTaintP: taintEntry =  {
                    taintBit: true,
                    map: initPropMap(result, true),
                    path: newPathNode(
                        `imprecise:${fname}`, 
                        joinTEPaths(argsTaint), getValue(s, result), getTc(s)),
                };
                
                // Update state
                let resultState: State = s;
                let resultElemId: Object | ID = F.eitherThrow(oid(s, result));
                let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultElemId, resultTaintP);
                let finalState: State = setMt(resultState, newMt);
                return F.Left(finalState);
            }
        },
    });
}


function definePropertyWrapPre( 
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
): Either<[State, any, any[]], Error> {
    // args: [obj: Object, propName: string | symbol, descriptor: PropertyDescriptor]
    // Unwrap the arguments except the descriptor.value (arg[2])
    let unwrapped_args = [];
    let si = s;
    let taintTrees = new WeakMap();
    for (let i in args) {
        if (i == '2') {
            let descriptor: PropertyDescriptor = args[i];
            let saveValue: Maybe<any> = F.Nothing();
            if (descriptor.value != undefined) {
                saveValue = F.Just(descriptor.value);
            }
            let trees: taintTree[] = [];
            let [siP, ui] = F.eitherThrow(unwrapObject(si, descriptor, trees));
            if (trees.length > 0) {
                taintTrees.set(ui, trees);
            }
            F.matchMaybe(saveValue, {
                Just: (value) => { ui.value = value },
                Nothing: () => {},
            });
            unwrapped_args.push(ui);
            si = siP;
        } else {
            let trees: taintTree[] = [];
            let [siP, ui] = F.eitherThrow(unwrapObject(si, args[i], trees));
            if (trees.length > 0) {
                taintTrees.set(ui, trees);
            }
            unwrapped_args.push(ui);
            si = siP;
        }
    }
    let siP: State = setTaintTreeMap(si, taintTrees);
    return F.Left([siP, base, unwrapped_args]);
}
