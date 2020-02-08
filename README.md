# JavaScript ASN1 Parser/Decoder PWA Library

This is library for a fork project of [PWA](https://github.com/SergioRando/PWA)

Full version can be found at [PWA Library](https://github.com/SergioRando/PWA-Library)

# Template
Read full installation process before executing any command

Install only if u need to test this template before tamplating yours own project

## 1. GitHub account
Register one GitHub account, if u dont have it already

## 2. Visual Studio Code
Download and install **Visual Studio Code** from official link https://code.visualstudio.com/

## 3. Install Command Line Tools
Super user password required
```
sudo apt-get install git make minify default-jre nodejs
```
* Git - required to execute git commands
* Make - required to execute Makefiles
* Minify - required for HTML/CSS minification
* Java Runtime Environment (JRE) - required to launch Google Closure Compiler
* NodeJS - required for testing libraries

## 4. PWA Project
- Create new [PWA project](https://github.com/SergioRando/PWA)
- Or open existing project (project must be a fork from [PWA template](https://github.com/SergioRando/PWA)

## 5. Create New Library
String Replacements
* _{Project Path}_ - path to drive with symlinks support (**NOT FAT32/NTFS/exFAT**)
* _{Username}_ - GitHub user name
* _{NewRepo}_ - GitHub new repository name (make it short and simple, start name with 'js-')

1. Create a **new empty repository** for your project on GitHub
_Note: without readme or any other files, total empty!_
2. Clone new repository
```
cd {Project Path}/src/lib
git clone https://github.com/{Username}/{NewRepo}.git
```
_Note: you can't copy link to new repo from GitHub project page, because its empty!_
3. Add ***PWA Library Template*** repository as an Upstream Remote
```
cd {NewRepo}
git remote add upstream https://github.com/SergioRando/js-lite.git
```
4. Update your fork
```
git pull upstream master
```
5. Push
```
git push origin master
```
6. Add submodule to project
```
cd {Project Path}/src/lib
git submodule add https://github.com/{Username}/{NewRepo}.git
```
7. You are ready to work with new project library

_Note: don't forget to change README.md_

## 6. Prepare

1. Remove Template block from README.md
2. Replace all 'js-lite' with '{NewRepo}'
3. Edit NOTICE

# Update
## Merge
To merge changes from template library
```
git fetch upstream
git merge upstream/master
```
## Errors
If you get error 'fatal: refusing to merge unrelated histories'
```
git merge upstream/master --allow-unrelated-histories
```
After this you will have to remove conflicts using VSC

# Install
Read full installation process before executing any command

Install only if u need to test this template before tamplating yours own project

## 1. GitHub account
Register one GitHub account, if u dont have it already

## 2. Visual Studio Code
Download and install **Visual Studio Code** from official link https://code.visualstudio.com/

## 3. Install Command Line Tools
Super user password required
```
sudo apt-get install git make minify default-jre nodejs
```
* Git - required to execute git commands
* Make - required to execute Makefiles
* Minify - required for HTML/CSS minification
* Java Runtime Environment (JRE) - required to launch Google Closure Compiler
* NodeJS - required for testing libraries

## 4. PWA Project
- Create new [PWA project](https://github.com/SergioRando/PWA)
- Or open existing project (project must be a fork from [PWA template](https://github.com/SergioRando/PWA)

## 5. Submodule
String Replacements
* _{Project Path}_ - path to drive with symlinks support (**NOT FAT32/NTFS/exFAT**)

```
cd {Project Path}/src/lib
git submodule add https://github.com/SergioRando/js-lite.git
```
_Note: don't forget to add notice about library license to yours project_

# Uninstall
String Replacements
* _{Project Path}_ - path to drive with symlinks support (**NOT FAT32/NTFS/exFAT**)
```
cd {Project Path}/src/lib
git submodule deinit js-lite
git rm js-lite
git commit -m "Removed submodule js-lite"
cd {Project Path}
rm -rf ./git/modules/src/lib/js-lite
```
_Note: be careful executing **rm** commands! It delete files permanenlty!_
