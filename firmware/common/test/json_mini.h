/*
 * Minimal JSON reader for the host test only (not used in firmware).
 * Supports objects, arrays, strings without escapes beyond \" and \\,
 * integers/floats, true/false/null -- enough for vectors/meshfind_vectors.json.
 */
#ifndef JSON_MINI_H
#define JSON_MINI_H

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } jtype;

typedef struct jnode {
    jtype t;
    const char *s; /* J_STR: points into source, not NUL-terminated */
    size_t slen;
    double num;
    int b;
    const char *key;
    size_t klen;
    struct jnode *child, *next;
} jnode;

static const char *jp;

static void jws(void) { while (*jp && isspace((unsigned char)*jp)) jp++; }

static jnode *jnew(jtype t)
{
    jnode *n = (jnode *)calloc(1, sizeof *n);
    if (!n) abort();
    n->t = t;
    return n;
}

static int jstr(const char **s, size_t *len)
{
    if (*jp != '"') return -1;
    *s = ++jp;
    while (*jp && *jp != '"') {
        if (*jp == '\\' && jp[1]) jp++;
        jp++;
    }
    if (*jp != '"') return -1;
    *len = (size_t)(jp - *s);
    jp++;
    return 0;
}

static jnode *jvalue(void)
{
    jnode *n;
    jws();
    if (*jp == '{' || *jp == '[') {
        int obj = *jp == '{';
        jnode **tail;
        n = jnew(obj ? J_OBJ : J_ARR);
        tail = &n->child;
        jp++;
        jws();
        if (*jp == (obj ? '}' : ']')) { jp++; return n; }
        for (;;) {
            const char *k = NULL;
            size_t kl = 0;
            jnode *c;
            jws();
            if (obj) {
                if (jstr(&k, &kl)) return NULL;
                jws();
                if (*jp++ != ':') return NULL;
            }
            c = jvalue();
            if (!c) return NULL;
            c->key = k;
            c->klen = kl;
            *tail = c;
            tail = &c->next;
            jws();
            if (*jp == ',') { jp++; continue; }
            if (*jp == (obj ? '}' : ']')) { jp++; return n; }
            return NULL;
        }
    }
    if (*jp == '"') {
        n = jnew(J_STR);
        return jstr(&n->s, &n->slen) ? NULL : n;
    }
    if (!strncmp(jp, "true", 4)) { jp += 4; n = jnew(J_BOOL); n->b = 1; return n; }
    if (!strncmp(jp, "false", 5)) { jp += 5; n = jnew(J_BOOL); return n; }
    if (!strncmp(jp, "null", 4)) { jp += 4; return jnew(J_NULL); }
    {
        char *end;
        double v = strtod(jp, &end);
        if (end == jp) return NULL;
        jp = end;
        n = jnew(J_NUM);
        n->num = v;
        return n;
    }
}

static jnode *jparse(const char *src)
{
    jp = src;
    return jvalue();
}

static jnode *jget(const jnode *o, const char *key)
{
    size_t kl = strlen(key);
    for (jnode *c = o ? o->child : NULL; c; c = c->next)
        if (c->klen == kl && !memcmp(c->key, key, kl)) return c;
    return NULL;
}

static long long jint(const jnode *o, const char *key)
{
    const jnode *n = jget(o, key);
    if (!n) return 0;
    return n->t == J_BOOL ? n->b : (long long)n->num;
}

/* Decodes hex string field into buf; returns byte length or -1. */
static int jhex(const jnode *o, const char *key, unsigned char *buf, size_t cap)
{
    const jnode *n = jget(o, key);
    size_t i;
    if (!n || n->t != J_STR || n->slen % 2 || n->slen / 2 > cap) return -1;
    for (i = 0; i < n->slen / 2; i++) {
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            char ch = n->s[2 * i + k];
            v <<= 4;
            if (ch >= '0' && ch <= '9') v |= (unsigned)(ch - '0');
            else if (ch >= 'a' && ch <= 'f') v |= (unsigned)(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') v |= (unsigned)(ch - 'A' + 10);
            else return -1;
        }
        buf[i] = (unsigned char)v;
    }
    return (int)(n->slen / 2);
}

#endif
