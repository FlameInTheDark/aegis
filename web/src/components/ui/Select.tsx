import * as SelectPrimitive from '@radix-ui/react-select'
import { Check, ChevronDown, ChevronUp } from 'lucide-react'
import { clsx } from 'clsx'

export interface SelectOption {
  value: string
  label: string
  disabled?: boolean
}

export interface SelectProps {
  value: string
  onValueChange: (value: string) => void
  options: SelectOption[]
  disabled?: boolean
  className?: string
  id?: string
  'aria-label'?: string
  'aria-labelledby'?: string
  placeholder?: string
  label?: string
  variant?: 'field' | 'chip'
}

// Encode every value so empty-string filters remain selectable in Radix.
const encode = (value: string) => `option:${value}`

export function Select({ value, onValueChange, options, disabled, className, id,
  'aria-label': ariaLabel, 'aria-labelledby': labelledBy, placeholder = 'Select…', label, variant = 'field',
}: SelectProps) {
  const selected = options.find((option) => option.value === value)
  return (
    <SelectPrimitive.Root value={selected ? encode(value) : ''} onValueChange={(next) => onValueChange(next.slice(7))} disabled={disabled || options.length === 0}>
      <SelectPrimitive.Trigger id={id} aria-label={ariaLabel ?? label} aria-labelledby={labelledBy}
        className={clsx('aegis-select-trigger', variant === 'chip' && 'aegis-select-chip', className)}>
        {label && <span className="tbl-chip-label">{label}:</span>}
        <span className="aegis-select-value"><SelectPrimitive.Value placeholder={placeholder} /></span>
        <SelectPrimitive.Icon className="aegis-select-chevron"><ChevronDown size={14} aria-hidden /></SelectPrimitive.Icon>
      </SelectPrimitive.Trigger>
      <SelectPrimitive.Portal>
        <SelectPrimitive.Content position="popper" sideOffset={6} collisionPadding={12} className="aegis-select-content"
          onClick={(event) => event.stopPropagation()}
          onEscapeKeyDown={(event) => event.stopPropagation()}
          onKeyDown={(event) => event.stopPropagation()}>
          <SelectPrimitive.ScrollUpButton className="aegis-select-scroll"><ChevronUp size={14} aria-hidden /></SelectPrimitive.ScrollUpButton>
          <SelectPrimitive.Viewport className="aegis-select-viewport">
            {options.map((option) => (
              <SelectPrimitive.Item key={option.value} value={encode(option.value)} disabled={option.disabled}
                textValue={option.label} className="aegis-select-option">
                <SelectPrimitive.ItemText>{option.label}</SelectPrimitive.ItemText>
                <SelectPrimitive.ItemIndicator className="aegis-select-check"><Check size={14} aria-hidden /></SelectPrimitive.ItemIndicator>
              </SelectPrimitive.Item>
            ))}
          </SelectPrimitive.Viewport>
          <SelectPrimitive.ScrollDownButton className="aegis-select-scroll"><ChevronDown size={14} aria-hidden /></SelectPrimitive.ScrollDownButton>
        </SelectPrimitive.Content>
      </SelectPrimitive.Portal>
    </SelectPrimitive.Root>
  )
}
