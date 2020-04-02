export const Some = (promises, predicate) => {
  return new Promise((resolve, reject) => {
    let finishedCount = 0
    const sharedState = { resolved: false }
    const resultArr = new Array(promises.length).fill(undefined)
    promises.forEach((x, index) => {
      x.then((resp) => {
        resultArr[index] = resp
        return undefined
      })
        .catch((_) => {})
        .finally(() => {
          if (sharedState.resolved) return
          predicate(resultArr.slice(0), sharedState)
            .then((data) => {
              sharedState.resolved = true
              resolve(data)
              return undefined
            })
            .catch((_) => {})
            .finally((_) => {
              finishedCount += 1
              if (finishedCount === promises.length) {
                reject(new Error(`Unable to resolve enough promises, responses: ${JSON.stringify(resultArr)}`))
              }
            })
        })
    })
  })
}
