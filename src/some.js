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
                reject(
                  new Error(
                    `Unable to resolve enough promises, errors: ${JSON.stringify(errorArr)}, responses: ${JSON.stringify(resultArr)}, predicate: ${
                      predicateError.message || predicateError
                    }`
                  )
                )
              }
            })
        })
    })
  })
