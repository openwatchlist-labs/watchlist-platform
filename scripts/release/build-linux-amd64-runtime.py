#!/usr/bin/env python3
from __future__ import annotations
import argparse, gzip, hashlib, json, os, pathlib, stat, tarfile, tempfile

RUNTIME_FILES = [
    ("bin/linux-amd64/platform-api", "bin/platform-api"),
    ("bin/linux-amd64/platform-ops", "bin/platform-ops"),
    ("bin/linux-amd64/container-healthcheck", "bin/container-healthcheck"),
    ("bin/linux-amd64/catalog-mmap", "bin/catalog-mmap"),
]

def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def write_runtime_tree(assets: pathlib.Path, tree: pathlib.Path, version: str, vcs_ref: str, epoch: int) -> dict:
    files=[]
    for source_rel, target_rel in RUNTIME_FILES:
        source=assets/source_rel
        if not source.is_file():
            raise SystemExit(f"missing runtime executable: {source_rel}")
        target=tree/target_rel
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(source.read_bytes())
        target.chmod(0o755)
        files.append({"path":target_rel,"sha256":sha256(target),"size":target.stat().st_size,"mode":"0755"})
    manifest={
        "schema":"openwatchlist.linux-amd64-runtime-manifest.v1",
        "version":version,
        "vcs_ref":vcs_ref,
        "source_date_epoch":epoch,
        "target":{"os":"linux","arch":"amd64","rust_target":"x86_64-unknown-linux-gnu"},
        "files":files,
        "compiler_required_on_runtime_host":False,
        "publication_performed":False,
        "deployment_performed":False,
    }
    manifest_path=tree/"manifest.json"
    manifest_path.write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    lines=[]
    for path in sorted(p for p in tree.rglob("*") if p.is_file() and p.name!="SHA256SUMS"):
        lines.append(f"{sha256(path)}  ./{path.relative_to(tree).as_posix()}\n")
    (tree/"SHA256SUMS").write_text("".join(lines),encoding="utf-8")
    return manifest

def deterministic_tar(tree:pathlib.Path, output:pathlib.Path, prefix:str, epoch:int)->None:
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="",mode="wb",fileobj=raw,mtime=epoch,compresslevel=9) as gz:
            with tarfile.open(fileobj=gz,mode="w",format=tarfile.USTAR_FORMAT) as tf:
                for p in sorted(tree.rglob("*")):
                    rel=p.relative_to(tree).as_posix(); name=f"{prefix}/{rel}"
                    info=tarfile.TarInfo(name=name); info.uid=0; info.gid=0; info.uname=""; info.gname=""; info.mtime=epoch
                    if p.is_dir(): info.type=tarfile.DIRTYPE; info.mode=0o755; tf.addfile(info)
                    elif p.is_file():
                        info.size=p.stat().st_size; info.mode=0o755 if rel.startswith("bin/") else 0o644
                        with p.open("rb") as f: tf.addfile(info,f)

def main()->None:
    p=argparse.ArgumentParser()
    p.add_argument("--assets-root",required=True); p.add_argument("--version",required=True); p.add_argument("--vcs-ref",required=True)
    p.add_argument("--source-date-epoch",required=True,type=int); p.add_argument("--archive",required=True); p.add_argument("--manifest",required=True)
    a=p.parse_args(); assets=pathlib.Path(a.assets_root); archive=pathlib.Path(a.archive); manifest_out=pathlib.Path(a.manifest)
    archive.parent.mkdir(parents=True,exist_ok=True); manifest_out.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="openwatchlist-linux-runtime-") as td:
        tree=pathlib.Path(td)/"tree"; tree.mkdir()
        manifest=write_runtime_tree(assets,tree,a.version,a.vcs_ref,a.source_date_epoch)
        deterministic_tar(tree,archive,f"openwatchlist-{a.version}-linux-amd64-runtime",a.source_date_epoch)
    manifest_out.write_text(json.dumps({**manifest,"archive":{"name":archive.name,"sha256":sha256(archive),"size":archive.stat().st_size}},indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"status":"PASS","archive":archive.name,"sha256":sha256(archive),"file_count":len(manifest["files"])},indent=2,sort_keys=True))
if __name__=="__main__": main()
