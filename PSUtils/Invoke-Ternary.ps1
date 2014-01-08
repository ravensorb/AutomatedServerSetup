# ---------------------------------------------------------------------------
# Name:   Invoke-Ternary
# Alias:  ?:
# Author: Karl Prosser
# Desc:   Similar to the C# ? : operator e.g.
#            _name = (value != null) ? String.Empty : value;
# Usage:  1..10 | ?: {$_ -gt 5} {"Greater than 5;$_} {"Not greater than 5";$_}
# ---------------------------------------------------------------------------
set-alias ?: Invoke-Ternary -Option AllScope -Description "PSCX filter alias"
filter Invoke-Ternary ([scriptblock]$decider, [scriptblock]$ifTrue, [scriptblock]$ifFalse)
{
   if (&$decider) { 
      &$ifTrue
   } else { 
      &$ifFalse 
   }
}