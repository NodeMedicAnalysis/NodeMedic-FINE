import { modulePolicy, ExternalMethodTaintPolicy, externalMethodTaintPolicyDispatch, externalMethodWrapperPolicyDispatch, ExternalMethodWrapPrePolicy, WrapperPolicyType } from './PolicyInterface';
import { State } from '../State';
import { Wrapped, Unwrapped } from '../Wrapper';
import { F, Either, ExternalFunction } from '../Flib';
import { getObjectPolicy } from './PolicyManager';


export const LodashPolicy: modulePolicy = {

    externalMethodWrapperPolicies: {
        'each': {
            pre: F.Just(eachWrapPre),
            post: F.Nothing(),
        },
        'forEach': {
            pre: F.Just(eachWrapPre),
            post: F.Nothing(),
        },
    },

    externalMethodTaintPolicies: {},

    // Not used
    isTainted(s: State, v: Wrapped) { return true },

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
        return F.matchMaybe(externalMethodWrapperPolicyDispatch(this.externalMethodWrapperPolicies, f as Function, WrapperPolicyType.pre), {
            Just: (policy: ExternalMethodWrapPrePolicy) => F.eitherThrow(policy(s, f as Function, base, args)),
            // Fall back to Object policy
            Nothing: () => getObjectPolicy().WInvokeFunPre(s, f, base, args),
        });
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
        return F.matchMaybe(externalMethodTaintPolicyDispatch(this.externalMethodTaintPolicies, f), {
            Just: (policy: ExternalMethodTaintPolicy) => policy(s, f, base, args, result),
            // Fall back to Object policy
            Nothing: () => getObjectPolicy().TCall(s, f, base, args, result)
        });
    }
};



function eachWrapPre( 
    s: State,
    f: Function,
    base: Wrapped,
    args: Wrapped[],
): Either<[State, any, any[]], Error> {
    return F.Left(getObjectPolicy().WInvokeFunPre(s, f, base, args));
}
