"""모두를 위한 학교 콘서트장 만들기 - Streamlit + SQLite 협업 버전."""
from pathlib import Path
import re
import sqlite3
import streamlit as st
from streamlit.components.v1 import declare_component
from db import (initialize, register, authenticate, userid_exists, group_info,
                active_group_detail, group_snapshot, create_group, invite_members,
                respond_invite, leave_group, save_group_patch)

ROOT=Path(__file__).resolve().parent
initialize()
st.set_page_config(page_title="모두를 위한 학교 콘서트장 만들기",page_icon="🌿",layout="wide",initial_sidebar_state="collapsed")
st.markdown("""<style>
header[data-testid="stHeader"],footer,[data-testid="stSidebar"],[data-testid="stDecoration"]{display:none!important}
[data-testid="stMainBlockContainer"]{max-width:100%!important;padding:0!important;margin:0!important}
[data-testid="stAppViewContainer"]{background:#f6faf6}
[data-testid="stCustomComponent"]{margin:0!important;padding:0!important}
[data-testid="stCustomComponent"] iframe{width:100%!important;height:100dvh!important;border:0!important;display:block!important}
html,body{margin:0!important}
/* Only the HTML document owns vertical scrolling after login. */
body:has([data-testid="stCustomComponent"]){overflow:hidden!important}
body:has([data-testid="stCustomComponent"]) [data-testid="stAppViewContainer"]{height:100dvh!important;overflow:hidden!important}
body:has([data-testid="stCustomComponent"]) [data-testid="stMain"]{height:100dvh!important;overflow:hidden!important}
.gc-login-title{font-size:clamp(21px,3vw,39px);font-weight:900;white-space:nowrap;letter-spacing:-1.1px;color:#173525}
.gc-login-sub{font-weight:650;color:#48725a;margin:4px 0 30px}
@media(prefers-color-scheme:dark){
[data-testid="stAppViewContainer"]{background:#121a16!important;color:#e6eee9!important}
.gc-login-title{color:#ebf9ee!important}.gc-login-sub{color:#b1d2bb!important}
[data-testid="stMainBlockContainer"]{background:#121a16!important}
}
</style>""",unsafe_allow_html=True)

if 'user' not in st.session_state:st.session_state.user=None
if 'group_id' not in st.session_state:st.session_state.group_id=None
if 'last_event_id' not in st.session_state:st.session_state.last_event_id=None
if 'notice' not in st.session_state:st.session_state.notice=None
if 'registered_notice' not in st.session_state:st.session_state.registered_notice=False

if st.session_state.user is None:
    st.markdown('<div style="height:7vh"></div>',unsafe_allow_html=True)
    _,center,_=st.columns([.15,2.8,.15])
    with center:
        st.markdown('<div class="gc-login-title">🌿 모두를 위한 학교 콘서트장 만들기</div><div class="gc-login-sub">우리는 학교 축제 콘서트장 기획단!</div>',unsafe_allow_html=True)
        lt,rt=st.tabs(['로그인','신규등록'])
        with lt:
            with st.form('login'):
                userid=st.text_input('아이디(학번)')
                passwd=st.text_input('비밀번호',type='password')
                if st.form_submit_button('로그인',use_container_width=True,type='primary'):
                    user=authenticate(userid,passwd)
                    if user:
                        st.session_state.user=user
                        st.session_state.group_id=None
                        st.session_state.last_event_id=None
                        st.rerun()
                    st.error('아이디 또는 비밀번호를 확인하세요.')
        with rt:
            if st.session_state.get('registered_notice'):
                st.success('✅ 회원가입이 완료되었습니다. 로그인 탭에서 학번과 비밀번호로 로그인하세요.')

            # Streamlit 기본 위젯만 사용합니다. 사용자 정의 컴포넌트 경로에
            # 의존하지 않으므로 클라우드 배포 환경에서도 등록 창이 표시됩니다.
            new_name=st.text_input('이름',key='new_student_name',max_chars=40)
            left,right=st.columns([3,2],vertical_alignment='bottom')
            with left:
                new_id=st.text_input('아이디(학번)',key='new_student_id',max_chars=15,
                                     placeholder='숫자 4~15자리')
            with right:
                if new_id.strip():
                    if not re.fullmatch(r'[0-9]{4,15}',new_id.strip()):
                        st.caption('학번은 숫자 4~15자리로 입력하세요.')
                    elif userid_exists(new_id):
                        st.error('이미 등록된 아이디입니다.',icon='⚠️')
                else:
                    st.caption(' ')
            new_password=st.text_input('비밀번호 (8자 이상)',type='password',
                                       key='new_student_password',max_chars=128)
            password_left,password_right=st.columns([3,2],vertical_alignment='bottom')
            with password_left:
                confirm_password=st.text_input('비밀번호 확인',type='password',
                                               key='new_student_confirm',max_chars=128)
            with password_right:
                if confirm_password:
                    if new_password == confirm_password:
                        st.success('비밀번호가 일치합니다.',icon='✅')
                    else:
                        st.error('비밀번호가 일치하지 않습니다.',icon='⚠️')
                else:
                    st.caption(' ')
            invalid_id=(not re.fullmatch(r'[0-9]{4,15}',new_id.strip()) or
                        userid_exists(new_id) if new_id else True)
            disabled=(not new_name.strip() or invalid_id or
                      len(new_password)<8 or new_password!=confirm_password)
            if st.button('신규등록',key='register_submit',type='primary',
                         use_container_width=True,disabled=disabled):
                ok,msg=register(new_name,new_id,new_password)
                if ok:
                    st.session_state.registered_notice=True
                    for field in ('new_student_name','new_student_id','new_student_password',
                                  'new_student_confirm'):
                        st.session_state[field]=''
                    st.rerun()
                else:
                    st.error(msg)
    st.stop()

me=st.session_state.user
# 이미 소속된 모둠이 있으면 로그인 직후 해당 공동 기록을 바로 사용합니다.
my_groups=group_info(me['id_num'])['groups']
if my_groups:
    if st.session_state.group_id not in [g['id'] for g in my_groups]:
        st.session_state.group_id=my_groups[0]['id']
else:
    st.session_state.group_id=None
component=declare_component('concert_collab',path=str(ROOT/'frontend'))

@st.fragment(run_every='3s')
def lesson():
    me=st.session_state.user
    gid=st.session_state.group_id
    detail=active_group_detail(me['id_num'],gid) if gid else None
    if gid and detail is None:
        st.session_state.group_id=None;gid=None
    info=group_info(me['id_num'])
    info['activeGroup']=detail
    if gid:
        snapshot,version=group_snapshot(me['id_num'],gid)
        context='group:'+str(gid)
    else:
        # 모둠에 가입하기 전에는 개인 학습 기록을 제공하지 않습니다.
        snapshot,version={},0
        context='onboarding'
    result=component(user=me['userid'],context=context,snapshot=snapshot,version=version,
        groupInfo=info,key='school_concert_'+str(me['id_num']),default=None,height=850)
    if not isinstance(result,dict):return
    event_id=result.get('event_id')
    if event_id==st.session_state.last_event_id:return
    st.session_state.last_event_id=event_id
    kind=result.get('type')
    try:
        if kind=='logout':
            if result.get('context')==context and result.get('patch'):
                if gid:save_group_patch(me['id_num'],gid,result['patch'])
                # 미가입 상태는 개인 기록을 저장하지 않습니다.
            st.session_state.user=None;st.session_state.group_id=None
            st.rerun(scope='app')
        elif kind=='save':
            if result.get('context')!=context:return
            patch=result.get('patch',{})
            if gid:save_group_patch(me['id_num'],gid,patch)
            # 미가입 상태는 학습 기록을 저장하지 않습니다.
        elif kind=='group_action':
            if result.get('context')==context and result.get('patch'):
                if gid:save_group_patch(me['id_num'],gid,result['patch'])
                # 미가입 상태는 개인 기록을 저장하지 않습니다.
            action=result.get('action');d=result.get('detail') or {}
            if action=='create':
                st.session_state.group_id=create_group(me['id_num'],d.get('name',''),d.get('members',[]),d.get('description',''))
            elif action=='switch':
                proposed=d.get('group_id')
                if not proposed or not active_group_detail(me['id_num'],int(proposed)):
                    raise ValueError('참여 중인 모둠만 선택할 수 있습니다.')
                st.session_state.group_id=int(proposed)
            elif action=='invite':
                if not gid:raise ValueError('모둠을 먼저 선택하세요.')
                invite_members(me['id_num'],gid,d.get('members',[]))
            elif action=='accept':
                respond_invite(me['id_num'],int(d['group_id']),True)
                st.session_state.group_id=int(d['group_id'])
            elif action=='decline':respond_invite(me['id_num'],int(d['group_id']),False)
            elif action=='leave':
                if not gid:raise ValueError('선택한 모둠이 없습니다.')
                leave_group(me['id_num'],gid)
                st.session_state.group_id=None
            st.rerun(scope='fragment')
    except (ValueError, KeyError, TypeError, sqlite3.IntegrityError) as e:
        st.error('처리할 수 없습니다: '+str(e))

lesson()
