# Force a colorful prompt
force_color_prompt=yes

PS1='[\[\033[1;36m\]\u\[\033[0m\]@\h ] [\w/]\$ '

export LS_OPTIONS='--color=auto'
eval "`dircolors`"
alias ls='ls $LS_OPTIONS'
alias ll='ls $LS_OPTIONS -l'
alias l='ls $LS_OPTIONS -lA'
#
# Some more alias to avoid making mistakes:
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'

