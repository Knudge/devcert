import path from 'path';
import { readFile, writeFile } from 'fs/promises';
import createDebug from 'debug';
import { sync as commandExists } from 'command-exists';
import { addCertificateToNSSCertDB, assertNotTouchingFiles, openCertificateInFirefox, closeFirefox, removeCertificateFromNSSCertDB } from './shared';
import { run, sudoAppend, pathExists } from '../utils';
import { Options } from '../index';
import UI from '../user-interface';
import { Platform } from '.';

const debug = createDebug('devcert:platforms:linux');

const DEBIAN_CA_PATH = '/usr/local/share/ca-certificates/devcert.crt';
const RHEL_CA_PATH = '/etc/pki/ca-trust/source/anchors/devcert.crt';

export default class LinuxPlatform implements Platform {

  private FIREFOX_NSS_DIR = path.join(process.env.HOME, '.mozilla/firefox/*');
  private CHROME_NSS_DIR = path.join(process.env.HOME, '.pki/nssdb');
  private FIREFOX_BIN_PATH = '/usr/bin/firefox';
  private CHROME_BIN_PATH = '/usr/bin/google-chrome';

  private HOST_FILE_PATH = '/etc/hosts';

  /**
   * Linux is surprisingly difficult. There seems to be multiple system-wide
   * repositories for certs, so we copy ours to each. However, Firefox does it's
   * usual separate trust store. Plus Chrome relies on the NSS tooling (like
   * Firefox), but uses the user's NSS database, unlike Firefox (which uses a
   * separate Mozilla one). And since Chrome doesn't prompt the user with a GUI
   * flow when opening certs, if we can't use certutil to install our certificate
   * into the user's NSS database, we're out of luck.
   */
  async addToTrustStores(certificatePath: string, options: Options = {}): Promise<void> {

    debug('Adding devcert root CA to Linux system-wide trust stores');
    run('sudo', ['cp', certificatePath, this.systemCAPath()]);
    this.updateSystemTrustStore();

    if (await this.isFirefoxInstalled()) {
      // Firefox
      debug('Firefox install detected: adding devcert root CA to Firefox-specific trust stores ...');
      if (!commandExists('certutil')) {
        if (options.skipCertutilInstall) {
          debug('NSS tooling is not already installed, and `skipCertutil` is true, so falling back to manual certificate install for Firefox');
          openCertificateInFirefox(this.FIREFOX_BIN_PATH, certificatePath);
        } else {
          debug('NSS tooling is not already installed. Trying to install NSS tooling now');
          this.installCertutil();
          debug('Installing certificate into Firefox trust stores using NSS tooling');
          await closeFirefox();
          await addCertificateToNSSCertDB(this.FIREFOX_NSS_DIR, certificatePath, 'certutil');
        }
      }
    } else {
      debug('Firefox does not appear to be installed, skipping Firefox-specific steps...');
    }

    if (await this.isChromeInstalled()) {
      debug('Chrome install detected: adding devcert root CA to Chrome trust store ...');
      if (!commandExists('certutil')) {
        UI.warnChromeOnLinuxWithoutCertutil();
      } else {
        await closeFirefox();
        await addCertificateToNSSCertDB(this.CHROME_NSS_DIR, certificatePath, 'certutil');
      }
    } else {
      debug('Chrome does not appear to be installed, skipping Chrome-specific steps...');
    }
  }
  
  async removeFromTrustStores(certificatePath: string) {
    try {
      run('sudo', ['rm', this.systemCAPath()]);
      this.updateSystemTrustStore();
    } catch (e) {
      debug(`failed to remove ${ certificatePath } from system trust store at ${ this.systemCAPath() }, continuing. ${ e.toString() }`);
    }
    if (commandExists('certutil')) {
      if (await this.isFirefoxInstalled()) {
        await removeCertificateFromNSSCertDB(this.FIREFOX_NSS_DIR, certificatePath, 'certutil');
      }
      if (await this.isChromeInstalled()) {
        await removeCertificateFromNSSCertDB(this.CHROME_NSS_DIR, certificatePath, 'certutil');
      }
    }
  }

  async addDomainToHostFileIfMissing(domain: string) {
    const trimDomain = domain.trim().replace(/[\s;]/g,'')
    let hostsFileContents = await readFile(this.HOST_FILE_PATH, 'utf8');
    if (!hostsFileContents.includes(trimDomain)) {
      sudoAppend(this.HOST_FILE_PATH, `127.0.0.1 ${trimDomain}\n`);
    }
  }

  async deleteProtectedFiles(filepath: string) {
    assertNotTouchingFiles(filepath, 'delete');
    run('sudo', ['rm', '-rf', filepath]);
  }

  async readProtectedFile(filepath: string) {
    assertNotTouchingFiles(filepath, 'read');
    return (await run('sudo', ['cat', filepath])).toString().trim();
  }

  async writeProtectedFile(filepath: string, contents: string) {
    assertNotTouchingFiles(filepath, 'write');
    if (await pathExists(filepath)) {
      await run('sudo', ['rm', filepath]);
    }
    await writeFile(filepath, contents);
    await run('sudo', ['chown', '0', filepath]);
    await run('sudo', ['chmod', '600', filepath]);
  }

  private usesUpdateCaTrust(): boolean {
    return commandExists('update-ca-trust');
  }

  private systemCAPath(): string {
    return this.usesUpdateCaTrust() ? RHEL_CA_PATH : DEBIAN_CA_PATH;
  }

  private updateSystemTrustStore(): void {
    if (this.usesUpdateCaTrust()) {
      run('sudo', ['update-ca-trust']);
      return;
    }
    run('sudo', ['update-ca-certificates']);
  }

  private installCertutil(): void {
    if (commandExists('dnf')) {
      run('sudo', ['dnf', 'install', '-y', 'nss-tools']);
      return;
    }
    if (commandExists('yum')) {
      run('sudo', ['yum', 'install', '-y', 'nss-tools']);
      return;
    }
    run('sudo', ['apt', 'install', 'libnss3-tools']);
  }

  private isFirefoxInstalled() {
    return pathExists(this.FIREFOX_BIN_PATH);
  }

  private isChromeInstalled() {
    return pathExists(this.CHROME_BIN_PATH);
  }

}
