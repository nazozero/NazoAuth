#!/usr/bin/env bash
# Compare the post-refactor default and the two peers on one prepared fixture.
set -euo pipefail
cd "$(dirname "$0")"
case ${1:-} in
  prepare) bash check-defaults.sh ;;
  k6)
    # Rotate first, middle and last place once at each fixed load.
    for rate in 400 2400 4375; do
      bash policy-peers.sh machine D-$rate-71 K-$rate-71 H-$rate-71 \
        K-$rate-72 H-$rate-72 D-$rate-72 H-$rate-73 D-$rate-73 K-$rate-73
    done
    bash policy-peers.sh introspect H-2400-81 D-2400-81 K-2400-81 \
      D-2400-82 K-2400-82 H-2400-82 K-2400-83 H-2400-83 D-2400-83
    ;;
  wrk2)
    # Use the same starting load, search algorithm and connections for each product.
    for arm in D K H; do BENCH_WRK2_CONNECTIONS=960 bash policy-wrk2.sh "$arm" machine 400; done
    for arm in K H D; do BENCH_WRK2_CONNECTIONS=960 bash policy-wrk2.sh "$arm" introspect 2400; done
    for arm in H D K; do BENCH_WRK2_CONNECTIONS=64 bash policy-wrk2.sh "$arm" machine 400; done
    for arm in K D H; do BENCH_WRK2_CONNECTIONS=15 bash policy-wrk2.sh "$arm" machine 400; done
    ;;
  k6-high)
    for rate in 6000 6750 7500 9000 12000; do
      bash policy-peers.sh machine D-$rate-91 K-$rate-91 H-$rate-91 \
        K-$rate-92 H-$rate-92 D-$rate-92 H-$rate-93 D-$rate-93 K-$rate-93
    done
    ;;
  wrk2-check)
    # Test whether the query search is sensitive to its starting rate.
    for arm in H D K; do
      BENCH_WRK2_CONNECTIONS=960 bash policy-wrk2.sh "$arm" introspect 9600 "$PWD/results/second-start"
    done
    # Continue below the initial grid only when none of its three rates passed.
    for summary in "$PWD"/results/wrk2*/*/machine/summary.json; do
      case $(jq -r .status "$summary") in
        no-accepted-starting-rate)
          rate=$(jq -r '.first_rejected_rate / 2 | floor' "$summary")
          ceiling=131072 ;;
        confirmation-failed)
          rate=$(jq -r '[.trials[] | select(.confirmation and (.accepted|not)) | .offered_per_second] | min' "$summary")
          rate=$(jq -r --argjson failed "$rate" '[.trials[] | select(.accepted and .offered_per_second < $failed) | .offered_per_second] | max // empty' "$summary")
          [[ -n $rate ]] || continue
          ceiling=$rate ;;
        *) continue ;;
      esac
      arm=$(basename "$(dirname "$(dirname "$summary")")")
      connections=$(jq -r '.trials[0].connections' "$summary")
      BENCH_WRK2_CONNECTIONS=$connections BENCH_WRK2_MAX_RATE=$ceiling \
        bash policy-wrk2.sh "$arm" machine "$rate" "$PWD/results/second-start"
    done
    ;;
  *) echo "Usage: bash compare-defaults.sh prepare|k6|wrk2|k6-high|wrk2-check" >&2; exit 2 ;;
esac
