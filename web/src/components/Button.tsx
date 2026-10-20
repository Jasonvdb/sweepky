import type { ComponentProps } from 'react'

/** pubky-app's pill variants as 04 names them; buttons.css draws each. */
export type ButtonVariant = 'primary' | 'default' | 'secondary'

/**
 * The classes for a pill in `variant`, so a link (a react-router `Link` or an
 * anchor to `#sweep`) can look like a button without being one.
 */
export function buttonClassName(variant: ButtonVariant): string {
  return `button button--${variant}`
}

type ButtonProps = Omit<ComponentProps<'button'>, 'className'> & {
  readonly variant: ButtonVariant
}

/**
 * A pill button. `type` defaults to `button`, not the HTML default `submit`,
 * so a button placed inside a form never submits it by accident.
 */
export function Button({ variant, type = 'button', ...rest }: ButtonProps) {
  return <button {...rest} type={type} className={buttonClassName(variant)} />
}
