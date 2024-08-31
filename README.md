# SEED_pyqt

## Java로 배포되어 있는 SEED 암호 알고리즘을 활용한 암복호화 프로그램(pyqt)
---
### 개발 기간
2024.05.01 ~ 2024.05.31
### 개발 환경
- OS : Ubuntu Linux(UTM 가상머신), mac
- GUI : python(pyqt)
- 암호 알고리즘 : https://seed.kisa.or.kr/kisa/Board/17/detailView.do 의 코드를 일부 수정하여 사용

### 주요 기능
- SEED 암호를 CBC, CCM, CTR, ECB, GCM 모드로 암복호화
- 개인키를 지정하여 사용
### 동작 흐름
- pyqt로 구현한 python에서 개인키, 모드, 원본파일을 지정 후 실행하면 해당 모드의 java 클래스 파일을 실행하여 원본파일에 대해 암호화된 파일을 생성.
### 개발 과정
1. pyqt의 원활한 사용을 위해 Ubuntu Linux 환경에서 GUI 구현. 이를 위해 UTM 가상머신을 사용.
2. KISA에서 무료 배포한 SEED 암호의 java 코드를 가져와서 파일을 읽어서 암호화 하도록 코드를 수정하고, 암호화 키 padding을 간략하게 구현함(부족한 비트만큼 '0'을 붙이는 방법)
3. pyqt로 구현한 코드를 mac 으로 가져와서 **파일 찾기**, **모드 선택**, **암복호화 선택**, **java 클래스 파일 실행** 기능을 구현.
### 화면 구성
<img width="612" alt="image" src="https://github.com/user-attachments/assets/bd6a4ad4-00f6-4500-8fc6-8ca9bfa6eae7">

### 트러블 슈팅
- (진행중) 윈도우 에서 파일 경로 지정시 발생하는 오류 수정 - 2024.08.31 ~
- 

