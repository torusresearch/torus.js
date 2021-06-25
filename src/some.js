function capitalizeFirstLetter(str) {
  return str.charAt(0).toUpperCase() + str.slice(1)
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
                // Filter same responses with same ID and extract non empty error messages
                const errors = Object.values(Object.fromEntries(resultArr.map((it) => [it?.id, it.error?.data])))
                  .filter((it) => typeof it === 'string' && it.length > 0)
                  .map((it) => (it.startsWith('Error occurred while verifying params') ? capitalizeFirstLetter(it.substr(37)) : it))
                if (errors.length > 0) {
                  // Format-able errors
                  const msg = errors.length > 1 ? `\n${errors.map((it) => `• ${it}`).join('\n')}` : errors[0]
                  reject(new Error(msg))
                } else {
                  reject(
                    new Error(
                      `Unable to resolve enough promises, errors: ${JSON.stringify(errorArr)}, responses: ${JSON.stringify(resultArr)}, predicate: ${
                        predicateError?.message || predicateError
                      }`
                    )
                  )
                }
              }
            })
        })
    })
  })
