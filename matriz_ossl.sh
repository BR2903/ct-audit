#!/usr/bin/env bash
# Matriz compiladores x flags sobre el ML-KEM nativo de OpenSSL (crypto/ml_kem/ml_kem.c)
# y agrega una fila por configuración a resultados.csv (mismas columnas que matriz.sh).
#
# Solo ml_kem.c se compila con el compilador/flags bajo prueba; el resto de libcrypto
# (SHA-3, CRYPTO_memcmp, etc.) viene de libcrypto.a, compilada UNA vez con el compilador
# por defecto. Antes de usar el script hay que compilar libcrypto.a (ver instrucciones).
#
# Uso:   ./matriz_ossl.sh <rol> <tag> "<niveles>" "<compiladores>" [iteraciones]
#        <tag> = carpeta $ROOT/<tag> con el código de OpenSSL ya compilado, p. ej. openssl-3.5.9
# Ej.:   ./matriz_ossl.sh auditoria openssl-3.5.9 "512 768 1024" "clang-18 gcc-14"
# Variables opcionales:
#   FLAGS="-O2 -flto;-Os"  flags personalizados separados por ; (como en matriz.sh)
#   CANARIO=1              control positivo: branch secreto inyectado en decap()
#   ABLACION=1             control positivo: todos los value_barrier de
#                          include/internal/constant_time.h se vuelven la identidad
#   CANARIO y ABLACION trabajan sobre COPIAS TEMPORALES; el código de OpenSSL no se modifica.

set -u
if [ $# -lt 4 ]; then
  sed -n '2,19p' "$0"; exit 1
fi
ROL=$1; TAG=$2; LVLS=$3; CCS=$4; ITERS=${5:-10}
ROOT=${CT_ROOT:-$HOME/ct-audit}
CSV=$ROOT/resultados.csv
HARNESS=$ROOT/harness_openssl.c
REPO=$ROOT/$TAG

[ -f "$REPO/libcrypto.a" ] || { echo "Falta $REPO/libcrypto.a: compila primero libcrypto (ver instrucciones)"; exit 1; }
COMMIT=$(git -C "$REPO" rev-parse --short=8 HEAD)
MLKEM=$REPO/crypto/ml_kem/ml_kem.c
EXTRA_INC=""
NOTA="original"
TMP=$(mktemp -d)

if [ "${CANARIO:-0}" = "1" ]; then
  cp "$MLKEM" "$TMP/ml_kem.c"
  sed -i '/CRYPTO_memcmp(ctext, tmp_ctext, vinfo->ctext_bytes));/a\    { static volatile int canario; if (mask) canario++; } /* CANARIO */' "$TMP/ml_kem.c"
  grep -q CANARIO "$TMP/ml_kem.c" || { echo "No se pudo inyectar el canario"; exit 1; }
  MLKEM=$TMP/ml_kem.c
  NOTA="canario"
fi

if [ "${ABLACION:-0}" = "1" ]; then
  mkdir -p "$TMP/inc/internal"
  cp "$REPO/include/internal/constant_time.h" "$TMP/inc/internal/"
  python3 - "$TMP/inc/internal/constant_time.h" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read(); n = 0
for name in ["value_barrier_bn", "value_barrier", "value_barrier_32", "value_barrier_64", "value_barrier_s"]:
    pat = re.compile(r"(static ossl_inline [\w ]+ %s\((\w[\w ]*) a\)\n\{)(.*?)(\n\})" % re.escape(name), re.S)
    s, k = pat.subn(lambda m: m.group(1) + "\n    return a; /* ABLACION */" + m.group(4), s); n += k
open(p, "w").write(s)
sys.exit(0 if n > 0 else 1)
PY
  [ $? -eq 0 ] || { echo "No se pudieron quitar los value barriers"; exit 1; }
  EXTRA_INC="-I$TMP/inc"
  NOTA="${NOTA/original/}"; NOTA="${NOTA:+$NOTA;}ablacion_sin_barrier"
fi

DEFS="-DOPENSSL_BUILDING_OPENSSL -DL_ENDIAN -DNDEBUG"
INCS="$EXTRA_INC -I$REPO -I$REPO/include -I$REPO/crypto/ml_kem"

if [ ! -f "$CSV" ]; then
  echo "fecha,libreria,commit,rol,operacion,kyber_k,compilador,version_compilador,flags,harness,iteraciones,decaps_ok,decaps_total,reportes_valgrind,ubicaciones_fuga,detalle_ubicaciones,notas" > "$CSV"
fi

FECHA=$(date -I)
for lvl in $LVLS; do
  k=$((lvl / 256))
  for cc in $CCS; do
    if ! command -v "$cc" >/dev/null; then echo "Saltando $cc (no instalado)"; continue; fi
    VER=$("$cc" --version 2>/dev/null | head -1)
    case $cc in gcc*) NOVEC="-O2 -fno-tree-vectorize" ;; *) NOVEC="-O2 -fno-vectorize" ;; esac
    if [ -n "${FLAGS:-}" ]; then
      IFS=';' read -r -a OPTS <<< "$FLAGS"
    else
      OPTS=("-O0" "-O1" "-O2" "-O3" "-Os" "$NOVEC")
    fi
    for opt in "${OPTS[@]}"; do
      bin=/tmp/ossl_${COMMIT}_${lvl}_${cc}_$(echo "$opt" | tr -d ' -' | tr '=' '_')

      if ! $cc $opt -g $DEFS $INCS -DLVL=$lvl "$HARNESS" "$MLKEM" "$REPO/libcrypto.a" \
           -lpthread -ldl -o "$bin" 2>/tmp/cc.err; then
        echo "$FECHA,openssl,$COMMIT,$ROL,decaps,$k,$cc,\"$VER\",\"$opt\",harness_openssl,$ITERS,,,,,,\"error de compilación;$NOTA\"" >> "$CSV"
        echo "ML-KEM-$lvl $cc [$opt] -> ERROR DE COMPILACIÓN (ver /tmp/cc.err)"
        continue
      fi

      OUT=$(valgrind -q "$bin" "$ITERS" 2>"$bin.vg")
      OK=$(echo "$OUT"  | sed -n 's/.*: \([0-9]*\)\/[0-9]* decaps.*/\1/p')
      TOT=$(echo "$OUT" | sed -n 's/.*: [0-9]*\/\([0-9]*\) decaps.*/\1/p')
      if [ -z "$OK" ] || grep -q "Process terminating" "$bin.vg"; then
        MOTIVO=$(grep -m1 -o "signal [0-9]* ([A-Z]*)" "$bin.vg")
        echo "$FECHA,openssl,$COMMIT,$ROL,decaps,$k,$cc,\"$VER\",\"$opt\",harness_openssl,$ITERS,,,,,,\"error de ejecución ${MOTIVO};$NOTA\"" >> "$CSV"
        echo "ML-KEM-$lvl $cc [$opt] -> ERROR DE EJECUCIÓN ${MOTIVO} (ver $bin.vg)"
        continue
      fi
      REP=$(grep -c 'Conditional jump\|Use of uninit' "$bin.vg")
      LOCS=$(grep -A1 'Conditional jump\|Use of uninit' "$bin.vg" | grep ' at ' | sed 's/.*: //' | sort -u)
      N=$(printf '%s' "$LOCS" | grep -c .)
      DET=$(printf '%s' "$LOCS" | tr '\n' ';' | sed 's/;$//')

      echo "$FECHA,openssl,$COMMIT,$ROL,decaps,$k,$cc,\"$VER\",\"$opt\",harness_openssl,$ITERS,$OK,$TOT,$REP,$N,\"$DET\",\"$NOTA\"" >> "$CSV"
      echo "ML-KEM-$lvl $cc [$opt] -> decaps $OK/$TOT | reportes $REP | ubicaciones con fuga: $N ${DET:+-> $DET}"
    done
  done
done
rm -rf "$TMP"
echo "Listo. Resultados agregados a $CSV"
