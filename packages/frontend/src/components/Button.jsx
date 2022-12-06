import React from 'react'
import './button.css'

export default ({ style, children, loadingText, onClick }) => {
  const [loading, setLoading] = React.useState(false)
  const [error, setError] = React.useState('')
  const handleClick = async () => {
    if (loading) return
    if (typeof onClick !== 'function') return
    try {
      setLoading(true)
      await onClick()
    } catch (err) {
      console.log(err)
      setError(err.toString())
      setTimeout(() => setError(''), 2000)
    } finally {
      setLoading(false)
    }
  }
  return (
    <div className="button-outer">
      <div className="button-inner" style={{ ...(style || {})}} onClick={handleClick}>
        {!loading && !error ? (
          <div className='button-text'>
            <div>{children}</div>
            <svg width="26" height="10" viewBox="0 0 26 10" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path fill-rule="evenodd" clip-rule="evenodd" d="M25.4714 5.47141C25.7318 5.21106 25.7318 4.78895 25.4714 4.5286L21.2288 0.28596C20.9684 0.0256108 20.5463 0.0256108 20.286 0.28596C20.0256 0.54631 20.0256 0.96842 20.286 1.22877L23.3905 4.33334L1.00002 4.33334C0.631832 4.33334 0.333355 4.63182 0.333355 5.00001C0.333355 5.3682 0.631832 5.66667 1.00002 5.66667L23.3905 5.66667L20.286 8.77124C20.0256 9.03159 20.0256 9.4537 20.286 9.71405C20.5463 9.9744 20.9684 9.9744 21.2288 9.71405L25.4714 5.47141Z" fill="#151616"/>
            </svg>
          </div>
        ) : null}
        {loading ? (loadingText ?? 'Loading...') : null}
        {error ? error : null}
      </div>
    </div>
  )
}
