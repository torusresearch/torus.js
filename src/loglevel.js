import Sentry from '@toruslabs/loglevel-sentry'
import loglevel from 'loglevel'

const logger = loglevel.getLogger('torus.js')

export const sentry = new Sentry({
  dsn: 'https://f4942c3615c3433ca3039681640aecf6@o503538.ingest.sentry.io/5596618',
  release: process.env.SENTRY_RELEASE,
  sampleRate: 0.5,
})
sentry.install(logger)

export default logger
