// AWS SDK for JavaScript v3 against s3rs, with the SDK's default integrity protection (CRC32
// checksums on uploads, sent as aws-chunked trailers; response checksum validation), managed
// multipart uploads (lib-storage), presigned URLs, copies, listings, tags and deletes.
//
//   S3RS_ENDPOINT=http://127.0.0.1:9000 S3RS_ACCESS_KEY=... S3RS_SECRET_KEY=... node tests/js-sdk.mjs
import {
  S3Client, CreateBucketCommand, PutObjectCommand, GetObjectCommand, HeadObjectCommand, ListObjectsV2Command,
  CopyObjectCommand, DeleteObjectsCommand, DeleteBucketCommand, PutObjectTaggingCommand, GetObjectTaggingCommand,
} from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { createHash, randomBytes } from 'node:crypto';

const endpoint = process.env.S3RS_ENDPOINT || 'http://127.0.0.1:9000';
const client = new S3Client({
  endpoint, region: 'us-east-1', forcePathStyle: true,
  credentials: { accessKeyId: process.env.S3RS_ACCESS_KEY || 'testkey', secretAccessKey: process.env.S3RS_SECRET_KEY || 'testsecret' },
});
const Bucket = 'js-sdk-' + randomBytes(4).toString('hex');
const md5 = (b) => createHash('md5').update(b).digest('hex');
const step = (s) => console.log('step:', s);
const body = async (r) => Buffer.from(await r.Body.transformToByteArray());

try {
  step('bucket + small object (default CRC32 checksum)');
  await client.send(new CreateBucketCommand({ Bucket }));
  const small = Buffer.from('hello from the js sdk\n');
  const put = await client.send(new PutObjectCommand({ Bucket, Key: 'small.txt', Body: small, ContentType: 'text/plain' }));
  if (!put.ChecksumCRC32) throw new Error('no CRC32 in the PUT response');
  const got = await client.send(new GetObjectCommand({ Bucket, Key: 'small.txt', ChecksumMode: 'ENABLED' }));
  if (!(await body(got)).equals(small) || got.ChecksumCRC32 !== put.ChecksumCRC32) throw new Error('small object mismatch');

  step('streamed upload of unknown length');
  const { Readable } = await import('node:stream');
  const streamData = randomBytes(300_000);
  await new Upload({ client, params: { Bucket, Key: 'stream.bin', Body: Readable.from([streamData.subarray(0, 100_000), streamData.subarray(100_000)]) } }).done();
  if (md5(await body(await client.send(new GetObjectCommand({ Bucket, Key: 'stream.bin' })))) !== md5(streamData)) throw new Error('stream mismatch');

  step('managed multipart upload (lib-storage, 4 parts)');
  const big = randomBytes(17 * 1024 * 1024);
  const up = new Upload({ client, params: { Bucket, Key: 'big.bin', Body: big }, partSize: 5 * 1024 * 1024, queueSize: 3 });
  await up.done();
  const head = await client.send(new HeadObjectCommand({ Bucket, Key: 'big.bin', ChecksumMode: 'ENABLED' }));
  if (head.ContentLength !== big.length || !head.ETag.endsWith('-4"')) throw new Error('multipart head: ' + JSON.stringify(head));
  if (md5(await body(await client.send(new GetObjectCommand({ Bucket, Key: 'big.bin' })))) !== md5(big)) throw new Error('multipart content');
  const range = await client.send(new GetObjectCommand({ Bucket, Key: 'big.bin', Range: 'bytes=5242870-5242889' }));
  if (!(await body(range)).equals(big.subarray(5242870, 5242890))) throw new Error('range across parts');

  step('presigned GET and PUT');
  const getUrl = await getSignedUrl(client, new GetObjectCommand({ Bucket, Key: 'small.txt' }), { expiresIn: 60 });
  if ((await (await fetch(getUrl)).text()) !== small.toString()) throw new Error('presigned GET');
  const putUrl = await getSignedUrl(client, new PutObjectCommand({ Bucket, Key: 'presigned.txt' }), { expiresIn: 60 });
  const r = await fetch(putUrl, { method: 'PUT', body: 'via presigned PUT' });
  if (!r.ok) throw new Error('presigned PUT: ' + r.status + ' ' + (await r.text()));

  step('copy, tags, listing, batch delete');
  await client.send(new CopyObjectCommand({ Bucket, Key: 'copy.bin', CopySource: `${Bucket}/big.bin` }));
  await client.send(new PutObjectTaggingCommand({ Bucket, Key: 'copy.bin', Tagging: { TagSet: [{ Key: 'k', Value: 'v' }] } }));
  const tags = await client.send(new GetObjectTaggingCommand({ Bucket, Key: 'copy.bin' }));
  if (tags.TagSet[0].Value !== 'v') throw new Error('tags');
  const list = await client.send(new ListObjectsV2Command({ Bucket }));
  const keys = list.Contents.map((o) => o.Key).sort();
  if (keys.join(',') !== 'big.bin,copy.bin,presigned.txt,small.txt,stream.bin') throw new Error('listing: ' + keys);
  const del = await client.send(new DeleteObjectsCommand({ Bucket, Delete: { Objects: keys.map((Key) => ({ Key })) } }));
  if ((del.Errors || []).length || del.Deleted.length !== keys.length) throw new Error('batch delete: ' + JSON.stringify(del));
  await client.send(new DeleteBucketCommand({ Bucket }));
  console.log('JS SDK TEST OK');
} catch (e) {
  console.error('JS SDK TEST FAILED:', e);
  process.exit(1);
}
