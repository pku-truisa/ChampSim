! Fortran memory allocation test for Object Tracer v3
!
! Tests Fortran ALLOCATE/DEALLOCATE tracking through malloc/free hooks.
! Modern gfortran (>=9) compiles ALLOCATE directly to malloc() calls,
! so they appear as type=1 in the trace. The tracer also hooks
! libgfortran's symbol list (CFI_allocate, for_allocate, etc.) for
! type=10 tagging when those symbols are detected at hook registration.
!
! Build:  gfortran -o test_fortran test_fortran.f90
! Run:    pin -t object_tracer_gemini.so -m malloc.bin -- ./test_fortran
! Check:  python3 -c "..." to see type counts

program test_fortran_alloc
  implicit none

  ! Allocatable arrays of various sizes
  real(kind=8), allocatable :: small_real(:)        ! 7 doubles = 56 bytes
  integer(kind=4), allocatable :: small_int(:)       ! 15 ints = 60 bytes
  complex(kind=8), allocatable :: small_cmplx(:)     ! 4 complexes = 64 bytes
  real(kind=8), allocatable :: medium_real(:)        ! 1024 doubles = 8 KiB
  real(kind=4), allocatable :: medium_float(:)       ! 2048 floats = 8 KiB
  real(kind=8), allocatable :: big_real(:)           ! 131072 doubles = 1 MiB
  integer(kind=8), allocatable :: big_int(:)         ! 500K int64 = ~3.81 MiB
  integer(kind=4), allocatable :: realloc_test(:)    ! 31 ints = 124 bytes

  integer :: i
  integer :: allocs = 0, frees = 0

  print *, '=== Fortran Tracer v3 Test ==='

  ! ================================================================
  ! Phase 1: Small ALLOCATE (< 64 bytes) → type=1 via malloc hook
  ! ================================================================
  print *, '--- Phase 1: Small ALLOCATE ---'
  allocate(small_real(7))      ! 56 bytes
  allocs = allocs + 1
  allocate(small_int(15))      ! 60 bytes
  allocs = allocs + 1
  allocate(small_cmplx(4))     ! 64 bytes
  allocs = allocs + 1
  small_real(1) = 1.1d0; small_int(1) = 10
  small_cmplx(1) = cmplx(1.0d0, -1.0d0, kind=8)
  print *, '  Phase 1: 3 allocs (type=1)'

  ! ================================================================
  ! Phase 2: Medium ALLOCATE (8 KiB) → type=1
  ! ================================================================
  print *, '--- Phase 2: Medium ALLOCATE ---'
  allocate(medium_real(1024))   ! 8192 bytes
  allocs = allocs + 1
  allocate(medium_float(2048))  ! 8192 bytes
  allocs = allocs + 1
  medium_real(1) = 3.14d0; medium_float(1) = 2.71
  print *, '  Phase 2: 2 allocs (type=1)'

  ! ================================================================
  ! Phase 3: Big ALLOCATE (>= 1 MiB) → may trigger mmap internally
  ! ================================================================
  print *, '--- Phase 3: Big ALLOCATE ---'
  allocate(big_real(131072))   ! 1 MiB
  allocs = allocs + 1
  allocate(big_int(500000))    ! ~3.81 MiB
  allocs = allocs + 1
  big_real(1) = 1.0d0; big_int(1) = 42
  print *, '  Phase 3: 2 allocs (type=1, may trigger internal mmap)'

  ! ================================================================
  ! Phase 4: DEALLOCATE → type=2 via free hook
  ! ================================================================
  print *, '--- Phase 4: DEALLOCATE ---'
  deallocate(small_int)
  frees = frees + 1
  deallocate(medium_float)
  frees = frees + 1
  deallocate(big_int)
  frees = frees + 1
  print *, '  Phase 4: 3 deallocs (type=2)'

  ! ================================================================
  ! Phase 5: Re-ALLOCATE after frees → type=1
  ! ================================================================
  print *, '--- Phase 5: Re-allocate ---'
  allocate(realloc_test(31))   ! 124 bytes
  allocs = allocs + 1
  realloc_test(1) = 999
  print *, '  Phase 5: 1 alloc (type=1)'

  ! ================================================================
  ! Summary
  ! ================================================================
  print *, '=== Test Complete ==='
  print *, ''
  print *, 'Active objects remaining (5):'
  print *, '  small_real(56B), small_cmplx(64B)'
  print *, '  medium_real(8KiB), big_real(1MiB)'
  print *, '  realloc_test(124B)'
  print *, ''
  print *, 'Expected trace counts:'
  write(*, '(A,I2,A)') '  User allocs: ', allocs, ' (all type=1 via malloc)'
  write(*, '(A,I2,A)') '  User frees:  ', frees, ' (all type=2 via free)'

end program test_fortran_alloc