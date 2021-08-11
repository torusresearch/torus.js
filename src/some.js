function capitalizeFirstLetter(str) {
  return str.charAt(0).toUpperCase() + str.slice(1)
}

export class SomeError extends Error {
  constructor({ errors, responses, predicate }) {
    super('Unable to resolve enough promises.')
    this.errors = errors
    this.responses = responses
    this.predicate = predicate
  }
}

export const Some = (promises, predicate) =>
  new Promise((resolve, reject) => {
    let finishedCount = 0
    const sharedState = { resolved: false }
    const errorArr = new Array(promises.length).fill(undefined)
    const resultArr = new Array(promises.length).fill(undefined)
    let predicateError
    promises.forEach((x, index) => {
      x.then((resp) => {
        resultArr[index] = resp
        return undefined
      })
        .catch((error) => {
          errorArr[index] = error
        })
        .finally(() => {
          if (sharedState.resolved) return
          predicate(resultArr.slice(0), sharedState)
            .then((data) => {
              sharedState.resolved = true
              resolve(data)
              return undefined
            })
            .catch((error) => {
              // log only the last predicate error
              predicateError = error
            })
            .finally((_) => {
              finishedCount += 1
              if (finishedCount === promises.length) {
                const errors = Object.values(
                  resultArr.reduce((acc, z) => {
                    const { id, error } = z || {}
                    if (error?.data?.length > 0) {
                      if (error.data.startsWith('Error occurred while verifying params')) acc[id] = capitalizeFirstLetter(error.data)
                      else acc[id] = error.data
                    }
                    return acc
                  }, {})
                )

                console.log(errors)
                if (errors.length > 0) {
                  // Format-able errors
                  const msg = errors.length > 1 ? `\n${errors.map((it) => `• ${it}`).join('\n')}` : errors[0]
                  reject(new Error(msg))
                } else {
                  reject(
                    new SomeError({
                      errors: errorArr,
                      responses: resultArr,
                      predicate: predicateError?.message || predicateError,
                    })
                  )
                }
              }
            })
        })
    })
  })
