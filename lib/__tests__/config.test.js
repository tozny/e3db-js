import assert from 'assert'
import { default as Config } from '../config'

describe('config', () => {
  it('has a default API url', () => {
    let c = new Config('', '', '', '', '')
    assert(c.apiUrl !== undefined, 'Config should set a default API url')
  })

  it('allows API url to be overridden', () => {
    let c = new Config('', '', '', '', '', 'https://test.com')
    assert('https://test.com' === c.apiUrl, 'Config should allow API url overrides')
  })
})
