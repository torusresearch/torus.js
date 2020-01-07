export const Some = (promises, count) => {
  return new Promise((resolve, reject) => {
    const resultArr = []
    if (promises.length < count) reject(new Error('Invalid count'))
    let successCount = 0
    let finishedCount = 0
    promises.forEach(x => {
      x.then(resp => {
        resultArr.push(resp)
        successCount++
      })
        .catch(_ => {})
        .finally(() => {
          finishedCount++
          if (successCount >= count) return resolve(resultArr)
          else if (finishedCount === promises.length) reject(new Error('Unable to resolve enough promises'))
        })
    })
  })
}
