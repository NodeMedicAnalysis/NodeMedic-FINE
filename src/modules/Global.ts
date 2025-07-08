import { modulePolicy } from './PolicyInterface';
import { State } from '../State';
import { Wrapped, Unwrapped } from '../Wrapper';
import { F, Either, ExternalFunction } from '../Flib';
import { imprecisePolicy } from './Object';
import { getTaintEntry, getValue } from '../Taint';
import { getObjectPolicy } from './PolicyManager';


export const GlobalPolicy: modulePolicy = {

    externalMethodWrapperPolicies: {},

    externalMethodTaintPolicies: {},

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
        return getObjectPolicy().TGetField(s, v1, v2, v3);
    },
    
    TPutField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error> {
        let tE3 = F.eitherThrow(getTaintEntry(s, v3));
        let u3 = getValue(s, v3);
        if (tE3.taintBit) {
            throw Error(`Attempted modification of global with ${String(u3)}`);
        } else {
            return F.Left(s);
        }
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
        F.assert(getValue(s, base) === global, `Base ${base} is not global`);
        // Get the taint entries
        let argsTaint = [];
        for (let i in args) {
            argsTaint.push(F.eitherThrow(getTaintEntry(s, args[i])));
        }
        let resultTaint = F.eitherThrow(getTaintEntry(s, result));
        return imprecisePolicy(f, s, F.Nothing(), argsTaint, resultTaint, result, this.isTainted);
    }
};
