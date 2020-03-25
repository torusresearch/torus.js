export const Some = (promises, predicate) => {
  return new Promise((resolve, reject) => {
    let finishedCount = 0
    let resolved = false
    const resultArr = new Array(promises.length).fill(undefined)
    promises.forEach((x, index) => {
      x.then((resp) => {
        resultArr[index] = resp
      })
        .catch((_) => {})
        .finally(() => {
          if (resolved) return
          predicate(resultArr.slice(0))
            .then((data) => {
              resolved = true
              resolve(data)
            })
            .catch((_) => {})
            .finally((_) => {
              finishedCount++
              if (finishedCount === promises.length) {
                reject(new Error('Unable to resolve enough promises, responses: ' + JSON.stringify(resultArr)))
              }
            })
        })
    })
  })
}
