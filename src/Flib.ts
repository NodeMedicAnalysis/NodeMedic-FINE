/*
 * @maintainer Darion Cassel
 *
 * A Library with some functional programming idioms, most notably
 * the constructs 'Maybe' and 'Either'.
 *
 * Maybe<A> has two variants: Just<A> and Nothing. This is useful for operations
 * that may otherwise produce a null value.
 * 
 * Either<A, B> has two variants: Left<A> and Right<B>. This is useful for operations
 * that may fail and produce an error, e.g. Either<ReturnValue, Error>.
 */
import { inspect } from 'util';


export type Primitive = number | string | boolean | symbol;
export type Literal = Primitive | Function;
export type NativeFunction = Function;
export type ExternalFunction = Function;

export interface Maybe<A> {
    value: A | symbol,
};

interface MaybeDestructure<A, B> {
    Just(_: A): B,
    Nothing(): B,
};

export interface Either<A, B> {
    left: A | symbol,
    right: B | symbol,
};

interface EitherDestructure<A, B, C> {
    Left(_: A): C,
    Right(_: B): C,
};

export class F {
    static NothingValue = Symbol("Nothing");
    static Just<A>(x: A): Maybe<A> {
        return {value: x}; 
    }
    static Nothing(): Maybe<any> {
        return {value: F.NothingValue};
    }
    static isJust<A>(x: Maybe<A>): boolean {
        if (x.value === F.NothingValue) {
            return false;
        } else {
            return true;
        }
    }
    static isNothing<A>(x: Maybe<A>): boolean {
        if (x.value === F.NothingValue) {
            return true;
        } else {
            return false;
        }
    }
    static maybeToNullable<A>(x: Maybe<A>): A | null {
        return F.isNothing(x) ? null : (x.value as A);
    }
    static nullableToMaybe<A>(x: A | null): Maybe<A> {
        return x == null ? F.Nothing()
                         : F.Just(x);
    }
    static matchMaybe<A, B>(val: Maybe<A>, destructure: MaybeDestructure<A, B>) {
        if (F.isJust (val)) {
            return destructure.Just (F.maybeToNullable (val));
        } else if (F.isNothing (val)) {
            return destructure.Nothing ();
        } else {
            throw Error(`Maybe destructure is neither Just nor Nothing: ${inspect(val)}`);
        }
    }
    static maybeThrow<A>(f: Maybe<A>, msg?: string): A {
        return F.matchMaybe(f, {
            Just: (x: A) => x,
            Nothing: () => {
                throw Error(msg ? msg : "Found nothing!");
            },
        });
    }
    static Left<A>(x: A): Either<A, any> {
        return {left: x, right: F.NothingValue}
    }
    static Right<B>(x: B): Either<any, B> {
        return {left: F.NothingValue, right: x}
    }
    static isLeft<A, B>(x: Either<A, B>): boolean {
        if (x.left !== F.NothingValue && x.right === F.NothingValue) {
            return true;
        } else {
            return false;
        }
    }
    static isRight<A, B>(x: Either<A, B>): boolean {
        if (x.right !== F.NothingValue && x.left === F.NothingValue) {
            return true;
        } else {
            return false;
        }
    }
    static getLeft<A, B>(x: Either<A, B>): A | null {
        return F.isLeft(x) ? (x.left as A) : null;
    }
    static getRight<A, B>(x: Either<A, B>): B | null {
        return F.isRight(x) ? (x.right as B) : null;
    }
    static matchEither<A, B, C>(val: Either<A, B>, destructure: EitherDestructure<A, B, C>) {
        if (F.isLeft (val)) {
            return destructure.Left (F.getLeft (val));
        } else if (F.isRight (val)) {
            return destructure.Right (F.getRight (val));
        } else {
            throw Error(`Either destructure is not Left or Right: ${inspect(val)}`);
        }
    }
    static eitherThrow<A, _>(f: Either<A, _>): A {
        return F.matchEither(f, {
            Left: (x: A) => x,
            Right: (err) => {
                throw err;
            },
        });
    }
    /** primitive ::= string | number | boolean | symbol */
    static isPrimitive(x: any): x is Primitive {
        if (['string', 'number', 'boolean', 'symbol'].indexOf(typeof x) != -1) {
            return true;
        } else {
            return false;
        }
    }
    static isFunction(x: any): x is Function {
        return typeof x === 'function';
    }
    static isUndefinedOrNull(x: any): x is undefined | null {
        if (x === undefined || x === null) {
            return true;
        } else {
            return false;
        }
    }
    /** literal ::= string | number | boolean | symbol | undefined | null */
    static isLiteral(x: any): x is Primitive | Function {
        if (F.isUndefinedOrNull(x) || F.isPrimitive(x)) {
            return true;
        } else {
            return false;
        }
    }
    static isString(x: any): x is String | string {
        return (typeof x == 'string') || (x instanceof String);
    }
    static isNativeFunction(x: Function): x is NativeFunction {
        F.assert(F.isFunction(x), `${inspect(x)} is not a function`);
        if (x.toString().indexOf('[native code]') == -1) {
            return false;
        }
        try {
            void new Function(x.toString());
        } catch (e) {
            return true;
        }
        return false;
    }
    static getFunctionName(f: Function): string {
        let name = f.hasOwnProperty('name') ? f.name : 'Anonymous Function';
        return name == '' ? 'Anonymous Function' : name;
    }
    static unimplemented(msg: string) {
        throw Error(`Unimplemented: ${msg}`);
    }
    static unreachable(msg: string) {
        throw Error(`Unreachable: ${msg}`);
    }
    static assert(cond: boolean, msg: string) {
        if (!cond) {
            throw Error(`Assertion failure: ${msg}`);
        }
    }
}
