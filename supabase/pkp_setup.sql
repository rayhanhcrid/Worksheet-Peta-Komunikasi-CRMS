-- Peta Komunikasi Personal worksheet (project "HCR Dashboard"), same pattern as the dwt_* worksheet.
-- One row per participant browser (device_id); participants write only through pkp_submit,
-- admins read/delete only through pkp_admin_list / pkp_admin_delete with the admin password
-- (salted sha256 in pkp_admin_config, 8 wrong tries per IP in 15 min = 15 min block).
-- The password itself is set separately so it never lands in this public repo.

create table if not exists public.pkp_submissions (
  id uuid primary key default gen_random_uuid(),
  device_id text not null unique,
  nama text not null default '',
  divisi text not null default '',
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists pkp_submissions_updated_idx on public.pkp_submissions (updated_at desc);

create table if not exists public.pkp_admin_config (
  id smallint primary key default 1 check (id = 1),
  salt text not null,
  code_hash text not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.pkp_admin_throttle (
  ip text primary key,
  fails integer not null default 0,
  first_fail_at timestamptz not null default now(),
  blocked_until timestamptz
);

alter table public.pkp_submissions enable row level security;
alter table public.pkp_admin_config enable row level security;
alter table public.pkp_admin_throttle enable row level security;
revoke all on public.pkp_submissions, public.pkp_admin_config, public.pkp_admin_throttle from anon, authenticated;

create or replace function public.pkp_submit(p_device text, p_nama text, p_divisi text, p_payload jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_at timestamptz;
begin
  if p_device is null or char_length(p_device) not between 6 and 64 then
    return jsonb_build_object('ok', false, 'error', 'Perangkat tidak dikenali.');
  end if;
  if btrim(coalesce(p_nama, '')) = '' then
    return jsonb_build_object('ok', false, 'error', 'Nama wajib diisi.');
  end if;
  if char_length(coalesce(p_payload, '{}'::jsonb)::text) > 40000 then
    return jsonb_build_object('ok', false, 'error', 'Isian terlalu panjang.');
  end if;

  insert into public.pkp_submissions (device_id, nama, divisi, payload, updated_at)
  values (p_device, left(btrim(p_nama), 120), left(btrim(coalesce(p_divisi, '')), 120), coalesce(p_payload, '{}'::jsonb), now())
  on conflict (device_id) do update
    set nama = excluded.nama, divisi = excluded.divisi, payload = excluded.payload, updated_at = now()
  returning updated_at into v_at;

  return jsonb_build_object('ok', true, 'at', v_at);
end; $$;

-- Internal: null when the password is right, otherwise the message to show.
create or replace function public.pkp_admin_check(p_code text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare
  v_hdr  text := current_setting('request.headers', true);
  v_ip   text := 'unknown';
  v_cfg  public.pkp_admin_config%rowtype;
  v_thr  public.pkp_admin_throttle%rowtype;
  v_next int;
begin
  if v_hdr is not null then
    v_ip := coalesce(nullif(btrim(split_part(v_hdr::json ->> 'x-forwarded-for', ',', 1)), ''), 'unknown');
  end if;

  select * into v_thr from public.pkp_admin_throttle where ip = v_ip;
  if found and v_thr.blocked_until is not null and v_thr.blocked_until > now() then
    return 'Terlalu banyak percobaan. Coba lagi dalam ' ||
      greatest(1, ceil(extract(epoch from (v_thr.blocked_until - now())) / 60))::int || ' menit.';
  end if;

  select * into v_cfg from public.pkp_admin_config where id = 1;
  if not found then
    return 'Password admin belum diatur.';
  end if;

  if encode(digest(v_cfg.salt || coalesce(p_code, ''), 'sha256'), 'hex') <> v_cfg.code_hash then
    v_next := case
      when v_thr.ip is null then 1
      when v_thr.first_fail_at < now() - interval '15 minutes' then 1
      else v_thr.fails + 1 end;
    insert into public.pkp_admin_throttle (ip, fails, first_fail_at, blocked_until)
    values (v_ip, v_next, now(), case when v_next >= 8 then now() + interval '15 minutes' end)
    on conflict (ip) do update
      set fails = v_next,
          first_fail_at = case when v_next = 1 then now() else public.pkp_admin_throttle.first_fail_at end,
          blocked_until = case when v_next >= 8 then now() + interval '15 minutes' end;
    return 'Password salah.';
  end if;

  delete from public.pkp_admin_throttle where ip = v_ip;
  return null;
end; $$;

create or replace function public.pkp_admin_list(p_code text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_err text; v_rows jsonb;
begin
  v_err := public.pkp_admin_check(p_code);
  if v_err is not null then
    return jsonb_build_object('ok', false, 'error', v_err);
  end if;
  select coalesce(jsonb_agg(t order by t.updated_at desc), '[]'::jsonb) into v_rows
  from (select id, nama, divisi, payload, created_at, updated_at from public.pkp_submissions) t;
  return jsonb_build_object('ok', true, 'rows', v_rows, 'at', now());
end; $$;

create or replace function public.pkp_admin_delete(p_code text, p_id uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_err text; v_n int;
begin
  v_err := public.pkp_admin_check(p_code);
  if v_err is not null then
    return jsonb_build_object('ok', false, 'error', v_err);
  end if;
  delete from public.pkp_submissions where id = p_id;
  get diagnostics v_n = row_count;
  return jsonb_build_object('ok', true, 'deleted', v_n);
end; $$;

revoke execute on function public.pkp_admin_check(text) from public, anon, authenticated;
revoke execute on function public.pkp_submit(text, text, text, jsonb) from public;
revoke execute on function public.pkp_admin_list(text) from public;
revoke execute on function public.pkp_admin_delete(text, uuid) from public;
grant execute on function public.pkp_submit(text, text, text, jsonb) to anon, authenticated;
grant execute on function public.pkp_admin_list(text) to anon, authenticated;
grant execute on function public.pkp_admin_delete(text, uuid) to anon, authenticated;

-- Set or change the admin password (run separately, replace GANTI_PASSWORD; do not commit it):
-- insert into public.pkp_admin_config (id, salt, code_hash)
-- select 1, s, encode(extensions.digest(s || 'GANTI_PASSWORD', 'sha256'), 'hex')
-- from (select encode(extensions.gen_random_bytes(16), 'hex') as s) x
-- on conflict (id) do update set salt = excluded.salt, code_hash = excluded.code_hash, updated_at = now();
