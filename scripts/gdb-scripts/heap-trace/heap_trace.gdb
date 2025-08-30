# heap-trace.gdb

set pagination off
set logging file heap_trace.log
set logging redirect on
set logging on

printf "=== HEAP TRACE GDB SCRIPT LOADED ===\n"

# Breakpoints
break malloc
break calloc
break realloc
break free

# Use this in commands instead of bt: fix old-version gdb (≤ 10.1) for “ui-out” bug
define btlog
    python import gdb, sys; sys.stderr.write(gdb.execute("bt", to_string=True))
end

# ---------- [ malloc ] ----------
commands 1
	silent
 	printf "\n========= [MALLOC] =========\n"
 	printf ">>> malloc(0x%lx)\n", (unsigned long)$rdi
	printf "Request size     : %lu\n", (unsigned long)$rdi
 	btlog
 	continue
end

# ---------- [ calloc ] ----------
commands 2
  	silent
  	printf "\n========= [CALLOC] =========\n"
  	printf ">>> calloc(%lu, 0x%lx)\n", (unsigned long)$rdi, (unsigned long)$rsi
  	printf "Count  : %lu\n", (unsigned long)$rdi
  	printf "Size   : %lu\n", (unsigned long)$rsi
 	btlog
  	continue
end

# ---------- [ realloc ] ----------
commands 3
  	silent
  	printf "\n========= [REALLOC] =========\n"
  	printf ">>> realloc(%p, 0x%lx)\n", (void*)$rdi, (unsigned long)$rsi
  	printf "Old ptr : %p\n", (void*)$rdi
  	printf "New size: %lu\n", (unsigned long)$rsi
  	btlog
  	continue
end

# ---------- [ free ] ----------
commands 4
  	silent
  	printf "\n========= [FREE] =========\n"
  	printf ">>> free(%p)\n", (void*)$rdi
  	printf "Freed pointer : %p\n", (void*)$rdi
  	btlog
  	continue
end

# ---------- [ signal handling + execution ] ----------
handle SIGABRT print stop
handle SIGSEGV print stop

run

# Crash / final state dump
printf "\n========= [CRASH INFO] =========\n"
bt
info registers
quit
