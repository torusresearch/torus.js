function capitalizeFirstLetter(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

export class SomeError<T> extends Error {
  errors: Error[];

  responses: T[];

  predicate: string;

  constructor({ errors, responses, predicate }: { errors: Error[]; responses: T[]; predicate: string }) {
    // its fine to log responses in errors logs for better debugging,
    // as data is always encrypted with temp key
    // temp key should not be logged anywhere
    const message = `Unable to resolve enough promises. 
      errors: ${errors.map((x) => x?.message || x).join(", ")}, 
      predicate error: ${predicate},
      ${responses.length} responses,
      responses: ${JSON.stringify(responses)}`;
    super(message);
    this.errors = errors;
    this.responses = responses;
    this.predicate = predicate;
  }

  get message() {
    return `${super.message}. errors: ${this.errors.map((x) => x?.message || x).join(", ")} and ${
      this.responses.length
    } responses: ${JSON.stringify(this.responses)},
      predicate error: ${this.predicate}`;
  }

  toString() {
    return this.message;
  }
}

export const Some = <K, T>(promises: Promise<K>[], predicate: (resultArr: K[], { resolved }: { resolved: boolean }) => Promise<T>): Promise<T> =>
  new Promise((resolve, reject) => {
    let finishedCount = 0;
    const sharedState = { resolved: false };
    const errorArr: Error[] = new Array(promises.length).fill(undefined);
    const resultArr: K[] = new Array(promises.length).fill(undefined);
    let predicateError: Error | string;
    // eslint-disable-next-line no-promise-executor-return
    return promises.forEach((x, index) => {
      return (
        x
          .then((resp: K) => {
            resultArr[index] = resp;
            return undefined;
          })
          .catch((error: Error) => {
            errorArr[index] = error;
          })
          // eslint-disable-next-line promise/no-return-in-finally
          .finally(() => {
            if (sharedState.resolved) return;
            return predicate(resultArr.slice(0), sharedState)
              .then((data) => {
                sharedState.resolved = true;
                resolve(data);
                return undefined;
              })
              .catch((error) => {
                // log only the last predicate error
                predicateError = error;
              })
              .finally(() => {
                finishedCount += 1;
                if (finishedCount === promises.length) {
                  const errors = Object.values(
                    resultArr.reduce((acc: Record<string, string>, z) => {
                      if (z) {
                        const { id, error } = z as { id?: string; error?: { data?: string } };
                        if (error?.data?.length > 0) {
                          if (error.data.startsWith("Error occurred while verifying params")) acc[id] = capitalizeFirstLetter(error.data);
                          else acc[id] = error.data;
                        }
                      }
                      return acc;
                    }, {})
                  );

                  if (errors.length > 0) {
                    // Format-able errors
                    const msg = errors.length > 1 ? `\n${errors.map((it) => `• ${it}`).join("\n")}` : errors[0];
                    reject(new Error(msg));
                  } else {
                    reject(
                      new SomeError({
                        errors: errorArr,
                        responses: resultArr,
                        predicate: (predicateError as Error)?.message || (predicateError as string),
                      })
                    );
                  }
                }
              });
          })
      );
    });
  });
