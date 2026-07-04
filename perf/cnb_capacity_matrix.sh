#!/usr/bin/env sh
set -eu

apk add --no-cache coreutils git jq python3 >/dev/null
docker compose version >/dev/null

mkdir -p docs perf/results
children_file="perf/results/cnb-capacity-children.txt"
: >"${children_file}"

run_capacity_child() {
  scenario="$1"
  suffix="$2"
  cpu_set="$3"
  log_path="perf/results/cnb-capacity-${suffix}.log"

  echo "starting capacity scenario ${scenario} on CPUs ${cpu_set} -> ${log_path}"
  (
    export CAPACITY_SCENARIOS="${scenario}"
    export CAPACITY_REPORT_SUFFIX="${suffix}"
    export PERF_CPUSET="${cpu_set}"
    export CNB_CAPACITY_SKIP_BOOTSTRAP=1
    export CNB_CAPACITY_COMMIT=0
    ./perf/cnb_capacity.sh
  ) >"${log_path}" 2>&1 &
  echo "$! ${suffix} ${log_path}" >>"${children_file}"
}

run_capacity_child token_only_client_credentials token-only 0-11
run_capacity_child oidc_cold_login_refresh oidc-cold-login 12-23
run_capacity_child oidc_logged_in_authorization_code oidc-logged-in 24-35
run_capacity_child oidc_refresh_only oidc-refresh-only 36-47
run_capacity_child fapi2_full_security fapi2-full-security 48-59

status=0
while read -r pid suffix log_path; do
  if [ -z "${pid}" ]; then
    continue
  fi
  if wait "${pid}"; then
    echo "capacity scenario ${suffix} completed"
  else
    child_status=$?
    status=1
    echo "capacity scenario ${suffix} failed with exit code ${child_status}"
    echo "last log lines for ${suffix}:"
    tail -n 120 "${log_path}" || true
  fi
done <"${children_file}"

if find docs -maxdepth 1 -name 'performance-capacity-curve-*.md' -print -quit | grep -q .; then
  git config user.name "${CNB_GIT_USER_NAME:-NazoAuth Capacity Bot}"
  git config user.email "${CNB_GIT_USER_EMAIL:-nazoauth-capacity-bot@noreply.cnb.cool}"
  git add docs/performance-capacity-curve-*.md
  if git diff --cached --quiet; then
    echo "No capacity report changes to commit."
  else
    git commit -m "Record CNB capacity curve matrix"

    BRANCH="${CNB_BRANCH:-main}"
    for attempt in 1 2 3; do
      if git pull --rebase origin "${BRANCH}" && git push origin "HEAD:${BRANCH}"; then
        exit "${status}"
      fi
      sleep $((attempt * 10))
    done

    git push origin "HEAD:${BRANCH}"
  fi
else
  echo "No capacity reports were generated."
  status=1
fi

exit "${status}"
