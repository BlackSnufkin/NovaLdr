@echo off
setlocal EnableDelayedExpansion

:: Set the password length and the character set for each category
set "length=32"
set "upper=ABCDEFGHIJKLMNOPQRSTUVWXYZ"
set "lower=abcdefghijklmnopqrstuvwxyz"
set "nums=0123456789"
set "symbols=!@#$%^&*()-_=+[{]}\|;:',<.>/?`~"

:: Combine all character sets
set "all=%upper%%lower%%nums%%symbols%"

:: Initialize an empty password
set "password="

:: Generate the random password
for /L %%i in (1, 1, %length%) do (
    set /a "index=!random! %% 104"
    for %%j in (!index!) do set "password=!password!!all:~%%j,1!"
)

:: Set the password as an environment variable
set "LITCRYPT_ENCRYPT_KEY=!password!"

:: Echo the generated password
echo Generated password: !password!

:: Execute the Rust program
cargo clean
cargo build --release
echo  %date%-%time%
endlocal