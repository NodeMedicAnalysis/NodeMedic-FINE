import { State } from '../State';
import { Wrapped, Unwrapped } from '../Wrapper';
import { Either, ExternalFunction, Maybe, F } from '../Flib';


export interface modulePolicy {
    externalMethodWrapperPolicies: Object,
    externalMethodTaintPolicies: Object,

    isTainted(s: State, value: Wrapped): boolean,

    WrapPre(s: State, value: Unwrapped): [State, Wrapped], 

    WGetField(s: State, r: Wrapped | Unwrapped): [State, Wrapped | Unwrapped],

    WPutFieldPre(s: State, v: Wrapped): [State, Wrapped | Unwrapped],

    WPutField(s: State, u: Unwrapped): [State, Wrapped | Unwrapped],

    WInvokeFunPre(s: State, f: Wrapped, base: Wrapped, args: Wrapped[]): [State, any, any[]],

    WInvokeFun(s: State,  f: any, base: any, args: any[], result: any): [State, any, any[], any],

    TGetField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error>,

    TPutField(s: State, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error>,
    
    TBinary(s: State, op: string, v1: Wrapped, v2: Wrapped, v3: Wrapped): Either<State, Error>,

    TUnary(s: State, v1: Wrapped, v2: Wrapped): Either<State, Error>,

    TCall(s: State, f: ExternalFunction, base: Wrapped, args: Wrapped[], result: Wrapped): Either<State, Error>,
}

export type ExternalMethodWrapPrePolicy = (
    s: State,
    f: ExternalFunction,
    base: Wrapped,
    args: Wrapped[],
) => Either<[State, any, any[]], Error>;

export type ExternalMethodWrapPostPolicy = (
    s: State,
    f: ExternalFunction,
    base: any,
    args: any[],
    result: any,
) => Either<[State, any, any[], any], Error>;

export enum WrapperPolicyType {
    pre,
    post,
}

export function externalMethodWrapperPolicyDispatch(
    policies: any, 
    f: ExternalFunction,
    policyType: WrapperPolicyType,
): Maybe<ExternalMethodWrapPrePolicy | ExternalMethodWrapPostPolicy> {
    if (policies.hasOwnProperty(f.name)) {
        // Apply one of our models
        if (policyType == WrapperPolicyType.pre) {
            return policies[f.name].pre as Maybe<ExternalMethodWrapPrePolicy>;
        } else if (policyType == WrapperPolicyType.post) {
            return policies[f.name].post as Maybe<ExternalMethodWrapPostPolicy>;
        } else {
            F.unreachable(`Unhandled policyType: ${policyType}`);
        }
    } else {
        return F.Nothing();
    }
}

export type ExternalMethodTaintPolicy = (
    s: State,
    f: ExternalFunction,
    base: Wrapped,
    args: Wrapped[],
    result: Wrapped,
) => Either<State, Error>;

export function externalMethodTaintPolicyDispatch(
    policies: any, 
    f: ExternalFunction
): Maybe<ExternalMethodTaintPolicy> {
    if (policies.hasOwnProperty(f.name)) {
        // Apply one of our models
        return F.Just(policies[f.name] as ExternalMethodTaintPolicy);
    } else {
        return F.Nothing();
    }
}
