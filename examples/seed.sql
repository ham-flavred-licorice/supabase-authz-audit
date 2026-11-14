-- Three synthetic users. A and B are the two test accounts; C exists so that B has
-- rows shared with someone who is not A.
insert into auth.users (id, email) values
  ('aaaaaaaa-0000-4000-8000-000000000001', 'user-a@authz-audit.test'),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'user-b@authz-audit.test'),
  ('cccccccc-0000-4000-8000-000000000003', 'user-c@authz-audit.test');

insert into public.profiles (id, display_name, bio) values
  ('aaaaaaaa-0000-4000-8000-000000000001', 'Alex (user A)', 'synthetic profile A'),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'Blake (user B)', 'synthetic profile B'),
  ('cccccccc-0000-4000-8000-000000000003', 'Casey (user C)', 'synthetic profile C');

insert into public.notes (id, user_id, title, body) values
  ('10000000-0000-4000-8000-0000000000a1', 'aaaaaaaa-0000-4000-8000-000000000001', 'A note one', 'private-to-A-note-body-one'),
  ('10000000-0000-4000-8000-0000000000a2', 'aaaaaaaa-0000-4000-8000-000000000001', 'A note two', 'private-to-A-note-body-two'),
  ('10000000-0000-4000-8000-0000000000b1', 'bbbbbbbb-0000-4000-8000-000000000002', 'B note one', 'private-to-B-note-body-one'),
  ('10000000-0000-4000-8000-0000000000b2', 'bbbbbbbb-0000-4000-8000-000000000002', 'B note two', 'private-to-B-note-body-two'),
  ('10000000-0000-4000-8000-0000000000c1', 'cccccccc-0000-4000-8000-000000000003', 'C note one', 'private-to-C-note-body-one');

insert into public.note_attachments (id, note_id, file_path) values
  ('20000000-0000-4000-8000-0000000000a1', '10000000-0000-4000-8000-0000000000a1', 'user-a/scan-a1.pdf'),
  ('20000000-0000-4000-8000-0000000000b1', '10000000-0000-4000-8000-0000000000b1', 'user-b/passport-b1.pdf'),
  ('20000000-0000-4000-8000-0000000000b2', '10000000-0000-4000-8000-0000000000b2', 'user-b/contract-b2.pdf');

insert into public.messages (id, sender_id, recipient_id, body) values
  ('30000000-0000-4000-8000-0000000000ab', 'aaaaaaaa-0000-4000-8000-000000000001', 'bbbbbbbb-0000-4000-8000-000000000002', 'shared-message-from-A-to-B'),
  ('30000000-0000-4000-8000-0000000000ba', 'bbbbbbbb-0000-4000-8000-000000000002', 'aaaaaaaa-0000-4000-8000-000000000001', 'shared-message-from-B-to-A'),
  ('30000000-0000-4000-8000-0000000000bc', 'bbbbbbbb-0000-4000-8000-000000000002', 'cccccccc-0000-4000-8000-000000000003', 'private-message-from-B-to-C'),
  ('30000000-0000-4000-8000-0000000000cb', 'cccccccc-0000-4000-8000-000000000003', 'bbbbbbbb-0000-4000-8000-000000000002', 'private-message-from-C-to-B'),
  ('30000000-0000-4000-8000-0000000000ac', 'aaaaaaaa-0000-4000-8000-000000000001', 'cccccccc-0000-4000-8000-000000000003', 'private-message-from-A-to-C');

insert into public.support_tickets (id, user_id, subject, body) values
  ('40000000-0000-4000-8000-0000000000a1', 'aaaaaaaa-0000-4000-8000-000000000001', 'A ticket', 'ticket-body-from-user-A'),
  ('40000000-0000-4000-8000-0000000000b1', 'bbbbbbbb-0000-4000-8000-000000000002', 'B ticket one', 'ticket-body-from-user-B-one'),
  ('40000000-0000-4000-8000-0000000000b2', 'bbbbbbbb-0000-4000-8000-000000000002', 'B ticket two', 'ticket-body-from-user-B-two');

insert into public.invoices (id, user_id, amount_cents, status) values
  ('50000000-0000-4000-8000-0000000000a1', 'aaaaaaaa-0000-4000-8000-000000000001', 1900, 'paid'),
  ('50000000-0000-4000-8000-0000000000b1', 'bbbbbbbb-0000-4000-8000-000000000002', 4900, 'paid'),
  ('50000000-0000-4000-8000-0000000000b2', 'bbbbbbbb-0000-4000-8000-000000000002', 4900, 'open'),
  ('50000000-0000-4000-8000-0000000000c1', 'cccccccc-0000-4000-8000-000000000003', 9900, 'paid');

insert into public.drafts (id, user_id, content) values
  ('60000000-0000-4000-8000-0000000000a1', 'aaaaaaaa-0000-4000-8000-000000000001', 'draft-content-of-user-A'),
  ('60000000-0000-4000-8000-0000000000b1', 'bbbbbbbb-0000-4000-8000-000000000002', 'draft-content-of-user-B-one'),
  ('60000000-0000-4000-8000-0000000000b2', 'bbbbbbbb-0000-4000-8000-000000000002', 'draft-content-of-user-B-two');

insert into public.plans (code, name, price_cents) values ('free', 'Free', 0), ('pro', 'Pro', 4900);
