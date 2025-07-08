import { modulePolicy, externalMethodTaintPolicyDispatch, ExternalMethodTaintPolicy } from './PolicyInterface';
import { State, taintEntry, PropMap, ID, setMt, setPath, getTc } from '../State';
import { newPathNode, PathNode, joinTEPaths, emptyPathNode } from '../TaintPaths';
import { Wrapped, Unwrapped } from '../Wrapper';
import { F, Either, Literal, NativeFunction, ExternalFunction } from '../Flib';
import { getTaintEntry, getValue, oid, initPropMap,
         setPropTaint, getPropTaint, anyPropertiesTainted } from '../Taint';
import { SafeMap } from '../DataStructures';
import { encodeStringFromEntry, decodeStringToEntry } from '../StringEncoding';
import { getObjectPolicy, policyPrecisionMap } from './PolicyManager';


export const StringPolicyPrecise: modulePolicy = {

    externalMethodWrapperPolicies: {},

    externalMethodTaintPolicies: {
        "blink": stringBlink,
        "substring": stringSubstring,
        "concat": stringConcat,
        "toUpperCase": stringToUpperCase,
        "toLowerCase": stringToLowerCase,
        "charCodeAt": stringCharCodeAt,
        "codePointAt": stringCodePointAt,
        "split": stringSplit,
    },

    // Not used
    isTainted(s: State, v: Wrapped) {
        const tE = F.eitherThrow(getTaintEntry(s, v));
        return tE.taintBit;
    },

    WrapPre(s: State, value: Unwrapped): [State, Wrapped] {
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
        let tE1: taintEntry = F.eitherThrow(getTaintEntry(s, v1));
        let tP2: PathNode = F.matchMaybe(s.Mt.get(F.eitherThrow(oid(s, v2))), {
            Just: (tE) => tE.path,
            Nothing: () => emptyPathNode(getValue(s, v2), getTc(s)),
        });
        return F.matchMaybe(tE1.map, {
            // Check if v2 is an element of the propMap, e.g.
            // an index corresponding to a string byte
            Just: (propMap: PropMap) => {
                let val2: Literal | Object = getValue(s, v2);
                // Properties must be strings in the PropMap
                let taintOfVal2 = F.matchMaybe(propMap.get(val2.toString()), {
                    Just: (t: boolean): boolean => t,
                    Nothing: (): boolean => false,
                });
                let taint = tE1.taintBit || taintOfVal2;
                let id3: ID | Object = F.eitherThrow(oid(s, v3));
                let MtP = s.Mt.set(id3, {
                    taintBit: taint,
                    map: initPropMap(v3, taint),
                    path: newPathNode(
                        'string.GetField', 
                        [tE1.path, tP2], getValue(s, v3), getTc(s)),
                });
                let sP = setMt(s, MtP);
                return F.Left(sP);
            },
            Nothing: () => {
                return getObjectPolicy().TGetField(s, v1, v2, v3);
            }
        });
    },
    
    TPutField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        return getObjectPolicy().TPutField(s, v1, v2, v3);
    },

    TBinary(s: State, op: string, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        if (op == '+') {
            let tE1: taintEntry = F.eitherThrow(getTaintEntry(s, v1));
            let tE2: taintEntry = F.eitherThrow(getTaintEntry(s, v2));
            let id3: ID | Object = F.eitherThrow(oid(s, v3));
            let uV1 = getValue(s, v1);
            let uV2 = getValue(s, v2);
            if (uV1 != undefined && uV2 != undefined) {
                // Apply precise string tainting
                let resultState: State = F.eitherThrow(preciseStringPolicy(
                    s, 
                    String.prototype.concat, 
                    uV1.toString(), 
                    tE1, 
                    [uV2.toString()], 
                    [tE2], 
                    id3
                ));
                return F.Left(resultState);
            } else {
                return getObjectPolicy().TBinary(s, op, v1, v2, v3);
            }
        } else {
            return getObjectPolicy().TBinary(s, op, v1, v2, v3);
        }
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
        // ************ Unsafe ***************
        let ubase = getValue(s, base);
        let uresult = getValue(s, result);
        // ***********************************
        F.assert(
            typeof ubase == 'string' || ubase === String || ubase === String.prototype, 
            `Base ${base} is not a string`
        );
        // String transformation? (string --> string)
        if (F.isString(uresult)) {
            // Get the taint entries
            let baseTaint = F.eitherThrow(getTaintEntry(s, base));
            let argsTaint = [];
            for (let i in args) {
                argsTaint.push(F.eitherThrow(getTaintEntry(s, args[i])));
            }
            // Get the actual values
            // ************ Unsafe ***************
            let uargs = [];
            for (let i in args) {
                uargs.push(getValue(s, args[i]));
            }
            // ************************************
            let idr: Object | ID = F.eitherThrow(oid(s, result));
            try {
                return preciseStringPolicy(s, f, ubase.toString(), baseTaint, uargs, argsTaint, idr);
            } catch (err) {
                // Fall back to module policies or imprecise policy
            }
        }
        return F.matchMaybe(externalMethodTaintPolicyDispatch(this.externalMethodTaintPolicies, f), {
            Just: (policy: ExternalMethodTaintPolicy) => policy(s, f as NativeFunction, base, args, result),
            // Fall back to Object policy
            Nothing: () => getObjectPolicy().TCall(s, f, base, args, result)
        });
    }
};

function preciseStringPolicy(
    s: State,
    f: NativeFunction,
    base: string,
    baseTaint: taintEntry,
    args: any[],
    argsTaint: taintEntry[],
    resultId: Object | ID,
): Either<State, Error> {
    F.assert(args.length == argsTaint.length, `Length of args != length of argsTaint`);
    let baseEncoded: string = F.eitherThrow(encodeStringFromEntry(base, baseTaint));
    let argsEncoded: string[] = [];
    let resultPaths: PathNode[] = [];
    resultPaths.push(baseTaint.path);
    for (let i = 0; i < args.length; i++) {
        resultPaths.push(argsTaint[i].path);
        if (F.isString(args[i])) {
            let argEncoded = F.eitherThrow(encodeStringFromEntry(args[i], argsTaint[i]));
            argsEncoded.push(argEncoded);
        } else {
            argsEncoded.push(args[i]);
        }
    }
    let resultEncoded: string;
    if (!F.isUndefinedOrNull(f.name))
        switch (f.name) {
            case 'slice':
            case 'substr':
            case 'substring':
                // @ts-ignore
                resultEncoded = Array.from(baseEncoded).slice(...argsEncoded).join('');
                break;
            default:
                resultEncoded = f.apply(baseEncoded, argsEncoded);
                break;
        }
    else {
        resultEncoded = f.apply(baseEncoded, argsEncoded);
    }
    let [resultStr, resultTaint]: [string, taintEntry] = F.eitherThrow(
        decodeStringToEntry(s, resultEncoded)
    );
    let fname = F.getFunctionName(f);
    let resultTaintP: taintEntry = {
        taintBit: resultTaint.taintBit,
        map: resultTaint.map,
        // The resulting path is the join of the base and args' paths
        path: newPathNode(
            `precise:string.${fname}`, resultPaths, resultStr, getTc(s)),
    }

    let resultState: State = s;
    resultState.Mt = resultState.Mt.set(resultId, resultTaintP);
    
    return F.Left(resultState);
}

// str.blink() 
function stringBlink(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {

    if (args.length != 0) {
        throw Error("stringBlink taint policy only supported for zero args");
    }

    // Get info about existing state
    let resultState: State = s;
    let baseVal: string = String(getValue(s, base));
    let baseTaint: taintEntry = F.eitherThrow(getTaintEntry(s, base));
    let resultTaint: taintEntry = F.eitherThrow(getTaintEntry(s, result));
    const BEGIN_BLINK = "<blink>";
    const END_BLINK = "</blink>";

    // Taint updating logic
    for (var i = 0; i < BEGIN_BLINK.length; i++) {
        resultTaint = setPropTaint(resultTaint, i.toString(), false);
    }
    for (var j = 0; j < baseVal.length; j++) {
        let originalTaint: boolean = getPropTaint(baseTaint, j.toString());
        resultTaint = setPropTaint(resultTaint, (BEGIN_BLINK.length + j).toString(), originalTaint);
    }
    for (var k = BEGIN_BLINK.length + baseVal.length; j < END_BLINK.length; k++) {
        resultTaint = setPropTaint(resultTaint, k.toString(), false);
    }

    let resultTaintP = setPath(
        resultTaint,
        newPathNode(
            'model:string.blink', [baseTaint.path], getValue(s, result), getTc(s))
    );

    // Update state
    let resultElemId: Object | ID = F.eitherThrow(oid(s, result));
    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultElemId, resultTaintP);
    let finalState: State = setMt(resultState, newMt);
    return F.Left(finalState);
}

// str.substring(indexStart[, indexEnd])
function stringSubstring(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {

    if (!(args.length == 1 || args.length == 2)) {
        throw Error("stringSubstring taint policy only supported for 1 or 2 args");
    }

    // Get info about existing state
    let resultState: State = s;
    let baseVal: string = String(getValue(s, base));
    let baseTaint: taintEntry = F.eitherThrow(getTaintEntry(s, base));
    let resultTaint: taintEntry = F.eitherThrow(getTaintEntry(s, result));

    // Taint updating logic
    let startIdx: number = Number(getValue(s, args[0]));
    let endIdx: number;
    if (args.length == 1) {
        endIdx = baseVal.length;
    } else {
        endIdx = Number(getValue(s, args[1]));
    }

    for (let j: number = startIdx; j < (endIdx - startIdx); j++) {
        let result_idx: number = j - startIdx;
        let originalTaint: boolean = getPropTaint(baseTaint, j.toString());
        resultTaint = setPropTaint(resultTaint, result_idx.toString(), originalTaint);
    }

    let resultTaintP = setPath(
        resultTaint,
        newPathNode(
            'model:string.substring', 
            [baseTaint.path], getValue(s, result), getTc(s))
    );

    // Update state
    let resultElemId: Object | ID = F.eitherThrow(oid(s, result));
    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultElemId, resultTaintP);
    let finalState: State = setMt(resultState, newMt);
    return F.Left(finalState);
}

// str.concat(str2 [, ...strN])
function stringConcat(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {

    if (args.length < 1) {
        throw Error("stringConcat taint policy only supported for at least 1 args");
    }

    // Get info about existing state
    let resultState: State = s;
    let baseTaint: taintEntry = F.eitherThrow(getTaintEntry(s, base));
    let resultTaint: taintEntry = F.eitherThrow(getTaintEntry(s, result));

    // Taint updating logic
    let baseVal: string = String(getValue(s, base));
    for (var i: number = 0; i < baseVal.length; i++) {
        let originalTaint: boolean = getPropTaint(baseTaint, i.toString());
        resultTaint = setPropTaint(resultTaint, i.toString(), originalTaint);
    }
    let offset = baseVal.length;
    for (var concat_arg = 0; concat_arg < args.length; concat_arg++) {
        let arg: string = String(getValue(s, args[concat_arg]));
        for (var j = 0; j < arg.length; j++) {
            let originalTaint: boolean = getPropTaint(baseTaint, j.toString());
            resultTaint = setPropTaint(resultTaint, (offset + j).toString(), originalTaint);
        }
        offset = offset + args.length;
    }

    let inTEs: taintEntry[] = [];
    inTEs.push(baseTaint);
    for (let i in args) {
        let argTE: taintEntry = F.eitherThrow(getTaintEntry(s, args[i]));
        inTEs.push(argTE);
    }

    let resultTaintP = setPath(
        resultTaint,
        newPathNode(
            'model:string.concat', joinTEPaths(inTEs), getValue(s, result), getTc(s))
    );
    
    // Update state
    let resultElemId: Object | ID = F.eitherThrow(oid(s, result));
    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultElemId, resultTaintP);
    let finalState: State = setMt(resultState, newMt);
    return F.Left(finalState);
}

// str.toUpperCase()
function stringToUpperCase(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {

    if (args.length != 0) {
        throw Error("stringToUpperCase taint policy only supported for zero args");
    }

    // Get info about existing state
    let resultState: State = s;
    let baseVal: string = String(getValue(s, base));
    let baseTaint: taintEntry = F.eitherThrow(getTaintEntry(s, base));
    let resultTaint: taintEntry = F.eitherThrow(getTaintEntry(s, result));

    // Taint updating logic
    if (baseTaint.taintBit) {
        for (let i: number = 0; i < baseVal.length; i++) {
            let originalTaint: boolean = getPropTaint(baseTaint, i.toString());
            resultTaint = setPropTaint(resultTaint, i.toString(), originalTaint);
        }
    }

    let resultTaintP = setPath(
        resultTaint,
        newPathNode(
            'model:string.toUpperCase', [baseTaint.path], getValue(s, result), getTc(s))
    );

    // Update state
    let resultElemId: Object | ID = F.eitherThrow(oid(s, result));
    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultElemId, resultTaintP);
    let finalState: State = setMt(resultState, newMt);
    return F.Left(finalState);
}

// str.toLowerCase()
function stringToLowerCase(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {

    if (args.length != 0) {
        throw Error("stringToLowerCase taint policy only supported for zero args");
    }

    // Get info about existing state
    let resultState: State = s;
    let baseVal: string = String(getValue(s, base));
    let baseTaint: taintEntry = F.eitherThrow(getTaintEntry(s, base));
    let resultTaint: taintEntry = F.eitherThrow(getTaintEntry(s, result));

    // Taint updating logic
    for (var i = 0; i < baseVal.length; i++) {
        let originalTaint: boolean = getPropTaint(baseTaint, i.toString());
        resultTaint = setPropTaint(resultTaint, i.toString(), originalTaint);
    }

    let resultTaintP = setPath(
        resultTaint,
        newPathNode(
            'model:string.toLowerCase', [baseTaint.path], getValue(s, result), getTc(s))
    );

    // Update state
    let resultElemId: Object | ID = F.eitherThrow(oid(s, result));
    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultElemId, resultTaintP);
    let finalState: State = setMt(resultState, newMt);
    
    return F.Left(finalState);
}

// str.charCodeAt(index)
function stringCharCodeAt(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {

    if (args.length != 1) {
        throw Error("stringCharCodeAt taint policy only supported for one arg");
    }
        
    // Get info about existing state
    let resultState: State = s;
    let baseTaint: taintEntry = F.eitherThrow(getTaintEntry(s, base));
    let resultTaint: taintEntry = F.eitherThrow(getTaintEntry(s, result));

    // Taint updating logic
    let index: number = Number(getValue(s, args[0]));
    resultTaint.taintBit = getPropTaint(baseTaint, index.toString());
    resultTaint.map = F.Nothing();

    let resultTaintP = setPath(
        resultTaint,
        newPathNode(
            'model:string.charCodeAt', [baseTaint.path], getValue(s, result), getTc(s))
    );

    // Update state
    let resultElemId: Object | ID = F.eitherThrow(oid(s, result));
    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultElemId, resultTaintP);
    let finalState: State = setMt(resultState, newMt);
    return F.Left(finalState);
}

// str.codePointAt(pos)
function stringCodePointAt(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {

    if (args.length != 1) {
        throw Error("stringCodePointAt taint policy only supported for one arg");
    }

    // Get info about existing state
    let resultState: State = s;
    let baseTaint: taintEntry = F.eitherThrow(getTaintEntry(s, base));
    let resultTaint: taintEntry = F.eitherThrow(getTaintEntry(s, result));

    // Taint updating logic
    let pos: number = Number(getValue(s, args[0]));
    resultTaint.taintBit = getPropTaint(baseTaint, pos.toString());
    resultTaint.map = F.Nothing();

    let resultTaintP = setPath(
        resultTaint,
        newPathNode(
            'model:string.codePointAt', [baseTaint.path], getValue(s, result), getTc(s))
    );

    // Update state
    let resultElemId: Object | ID = F.eitherThrow(oid(s, result));
    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultElemId, resultTaintP);
    let finalState: State = setMt(resultState, newMt);
    return F.Left(finalState);
}

// str.split([separator[, limit]])
function stringSplit(
    s: State,
    f: NativeFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
): Either<State, Error> {

    // Get info about existing state
    let resultState: State = s;
    let baseVal: string = String(getValue(s, base));
    let baseTaint: taintEntry = F.eitherThrow(getTaintEntry(s, base));
    let resultTaint: taintEntry = F.eitherThrow(getTaintEntry(s, result));

    // Unwrap result: Object to string[]
    let resultUnwrapped: Object = getValue(s, result);
    if (!(Array.isArray(resultUnwrapped))) {
        throw Error("stringSplit should return an array of strings");
    }
    let resultValue: string[] = Array.from<string>(resultUnwrapped);

    // Split by delimiter (at maximum [limit] number of times)
    let delimiter: string = ""; // Default argument
    let limit: number = baseVal.length; // Default argument
    if (args.length > 2) {
        throw Error("stringSplit taint policy only supported for two or fewer args");
    } 
    if (args.length > 0) {
        delimiter = String(getValue(s, args[0]));
        if (args.length == 2) {
            limit = Number(getValue(s, args[1]));
        }
    } else {
        // No args; no delimiter, no limit
        // Set taint entries for result[0] to that of base

        // For the purposes of default .split() taint arithmetic below, using an empty string as the delimiter
        // works as it is used to calculate the offset.
    }

    // Policy depends on whether arrays are handled precisely
    return F.matchMaybe(policyPrecisionMap.get('array'), {
        Just: (precisionLevel: string) => {
            if (precisionLevel == 'precise') {
                // StringSplit implicitly handles two arguments because the loop below uses result.length as the 
                // exit condition. This already takes into account the "limit" variable which would count
                // as an optional argument.
                let offset_idx = 0;
                let allTainted: boolean = true; // are all split strings tainted?
                for (let i = 0; i < resultValue.length; i++) {
                    let result_word: string = resultValue[i];
                    let resultElemId = F.eitherThrow(oid(s, result_word));
                    let resultTaintEntry: taintEntry = {
                        taintBit: false,
                        map: initPropMap(result_word, false),
                        path: newPathNode(
                            'model:string.split', 
                            [baseTaint.path], result_word, getTc(s)),
                    }
                    let allTaintedEntry: boolean = true; // are all indices in the string tainted?    
                    // Update taint for individual split word
                    for (var j = 0; j < result_word.length; j++) {
                        // Get taint from original base word
                        // offset_idx: sum of length of previous words in the split result
                        // j: index within current split word
                        // i*delimiter.length: sum of length of times the delimiter is used
                        let newIdx: number = offset_idx + j + i*delimiter.length;
                        let taint: boolean = getPropTaint(baseTaint, newIdx.toString());
                        // Apply taint to idx of split word
                        if (taint) {
                            resultTaintEntry = setPropTaint(resultTaintEntry, j.toString(), true);
                        }
                        allTaintedEntry = allTaintedEntry && taint;
                    }

                    resultTaintEntry.taintBit = allTaintedEntry;
                    allTainted = allTainted && allTaintedEntry;

                    // Update state for individual split word
                    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultElemId, resultTaintEntry);
                    resultState = setMt(resultState, newMt);  
                    // Increment offset by length of the split word
                    offset_idx = offset_idx + result_word.length;
                }

                // Update taintBit state for string array: set to true if all elems tainted 
                // (length is implicitly tainted)
                if (allTainted) {
                    let resultId: Object | ID = F.eitherThrow(oid(s, result));
                    resultTaint.taintBit = allTainted;
                    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultId, resultTaint);
                    resultState = setMt(resultState, newMt);
                }
                return F.Left(resultState);
            } else {
                // Imprecise
                let anyTainted: boolean = F.eitherThrow(anyPropertiesTainted(s, base));
                if (anyTainted) {
                    let resultId: Object | ID = F.eitherThrow(oid(s, result));
                    resultTaint.taintBit = true;
                    let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultId, resultTaint);
                    resultState = setMt(resultState, newMt);
                }
                return F.Left(resultState);
            }
        },
        Nothing: () => {
            // Default precision level is imprecise
            let anyTainted: boolean = F.eitherThrow(anyPropertiesTainted(s, base));
            if (anyTainted) {
                let resultId: Object | ID = F.eitherThrow(oid(s, result));
                resultTaint.taintBit = true;
                let newMt: SafeMap<Object | ID, taintEntry> = resultState.Mt.set(resultId, resultTaint);
                resultState = setMt(resultState, newMt);
            }
            return F.Left(resultState);
        },
    });
    
    
}
