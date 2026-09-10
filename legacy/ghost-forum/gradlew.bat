@echo off
setlocal

set GRADLE_HOME=%~dp0
set GRADLE_USER_HOME=%USERPROFILE%\.gradle

if "%JAVA_HOME%" == "" (
    echo Please set JAVA_HOME to point to your Java installation.
    exit /b 1
)

"%JAVA_HOME%\bin\java.exe" -Dorg.gradle.appname=%APP_BASE_NAME% -classpath "%GRADLE_HOME%\lib\gradle-launcher-8.5.jar" org.gradle.launcher.GradleMain %*