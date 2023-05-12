import consola, { LogLevel } from 'consola'
import path from 'path'
import yargs from 'yargs'
import process from 'process';
import { readdirSync } from 'fs'
import { spawn } from 'child_process'
import { stdout, stderr } from 'process';

const exec = (command: string, pipe?: boolean) => {

    console.log(`> ${command}`)

    const prc = spawn(command, {
        shell: true,
    });

    if(pipe || pipe === undefined) {
        prc.stdout.pipe(process.stdout);
        prc.stderr.pipe(process.stderr);
    }

    const stdoutData: string[] = [];
    const stderrData: string[] = [];
    prc.stdout.on('data', (data) => {
        stdoutData.push(data.toString());
    })
    prc.stderr.on('data', (data) => {
        stderrData.push(data.toString());
    })

    return new Promise((resolve, reject) => {
        prc.on('close', function (code) {
            console.log("")
            const output = {
                stdout: stdoutData.join(''),
                stderr: stderrData.join(''),
                code,
            }
            if (code === 0) {
                resolve(output);
            } else {
                reject(output);
            }
        });
    });
}

export async function processArgs(args: string[]) {
    // const parsed = await yargs.option('logLevel', {
    //     describe: 'set log level',
    //     choices: Object.keys(LogLevel),
    // }).argv

    // const logger = consola.create({ level: LogLevel[parsed.logLevel || 'Info'] })

    const repoDir = path.join(__dirname, '../..')
    const contractsDir = path.join(__dirname, '../../contracts')
    const cratesDir = path.join(__dirname, '../../crates')
    const cargoDir = `/usr/local/cargo`
    const rustupDir = `/usr/local/rustup`
    const dockerCacheDir = `${repoDir}/docker-cache`
    const rustupCacheDir = `${dockerCacheDir}/rustup`
    const cargoCacheDir = `${dockerCacheDir}/cargo`
    const relDirDockerCache = path.relative(repoDir, dockerCacheDir)
    const contractsCiVersion = '41abf440-20230503'
    const relDirContracts = path.relative(repoDir, contractsDir)
    const relDirCrates = path.relative(repoDir, cratesDir)
    const crates = readdirSync(cratesDir, { withFileTypes: true })
        .filter(dirent => dirent.isDirectory())
        .map(dirent => dirent.name);
    const contracts = readdirSync(contractsDir, { withFileTypes: true })
        .filter(dirent => dirent.isDirectory())
        .map(dirent => dirent.name);

    const addContractOption = (yargs: yargs.Argv) => {
        return yargs
        .option('contract', {
            type: 'array',
            demand: false,
            desc: 'Build a specific contract',
            default: contracts,
            choices: contracts,
        })
    }

    const addCrateOption = (yargs: yargs.Argv) => {
        return yargs
        .option('crate', {
            type: 'array',
            demand: false,
            desc: 'Build a specific crate',
            default: crates,
            choices: crates,
        })
    }

    const addToolchainOption = (yargs: yargs.Argv) => {
        return yargs
        .option('toolchain', {
            type: 'string',
            demand: false,
            desc: 'Use a specific toolchain',
            default: '',
        })
    }

    const addReleaseOption = (yargs: yargs.Argv) => {
        return yargs
        .option('release', {
            type: 'boolean',
            demand: false,
            desc: 'Build in release mode',
            default: false,
        })
    }

    const addFixOption = (yargs: yargs.Argv) => {
        return yargs
        .option('fix', {
            type: 'boolean',
            demand: false,
            desc: 'Fix the code',
            default: false,
        })
    }

    const addDockerOption = (yargs: yargs.Argv) => {
        return yargs
        .option('docker', {
            type: 'boolean',
            demand: false,
            desc: 'Use docker contracts-ci image to build instead of local toolchain',
            default: false,
        })
    }

    const initDocker = async () => {
        // check if the docker image is already pulled
        try {
            await exec(`docker images -q paritytech/contracts-ci-linux:${contractsCiVersion}`)
        } catch(e: any) {
            // if not, pull it
            await exec(`docker pull paritytech/contracts-ci-linux:${contractsCiVersion}`)

            // update the docker cache with the default rustup and cargo dirs from the newly pulled image
            await exec(`docker run --rm -v ${repoDir}/docker-cache:/docker-cache paritytech/contracts-ci-linux:${contractsCiVersion} cp -ur ${cargoDir} /${relDirDockerCache}/`)
            await exec(`docker run --rm -v ${repoDir}/docker-cache:/docker-cache paritytech/contracts-ci-linux:${contractsCiVersion} cp -ur ${rustupDir} /${relDirDockerCache}/`)
        }
    }

    const execCargo = async (argv: yargs.Arguments<{}>, cmd: string, cmdArgs: string, dir?: string) => {
        dir = dir ? dir : "."
        const toolchain = argv.toolchain ? `+${argv.toolchain}` : ''
        const relDir = path.relative(repoDir, dir)

        let script: string = "";
        if(argv.docker) {
            initDocker();
            script = `docker run --rm -v ${contractsDir}:/repo/${relDirContracts} -v ${cratesDir}:/repo/${relDirCrates} -v ${rustupCacheDir}:${rustupDir} -v ${cargoCacheDir}:${cargoDir} paritytech/contracts-ci-linux:${contractsCiVersion} cargo ${toolchain} ${cmd} --manifest-path=/repo/${relDir}/Cargo.toml ${cmdArgs}`
        } else {
            script = `cd ${repoDir} && cd ${dir} && cargo ${toolchain} ${cmd} ${cmdArgs}`
        }

        await exec(script)
        
        if(argv.docker) {
            // if running under docker, cache the docker rustup and cargo files
            // update any files which aren't already in the cache
            // this is done after the build, as the build will have updated the files / added dependencies to the cargo cache, etc
            await exec(`docker run --rm -v ${repoDir}/docker-cache:/docker-cache paritytech/contracts-ci-linux:${contractsCiVersion} cp -ur ${cargoDir} /${relDirDockerCache}/`)
            await exec(`docker run --rm -v ${repoDir}/docker-cache:/docker-cache paritytech/contracts-ci-linux:${contractsCiVersion} cp -ur ${rustupDir} /${relDirDockerCache}/`)
        }
    }

    await yargs
        // .usage('Usage: $0 [global options] <command> [options]')
        .command(
            'build',
            'Build the contracts',
            (yargs) => {
                // cannot build crates
                yargs = addContractOption(yargs)
                yargs = addToolchainOption(yargs)
                yargs = addReleaseOption(yargs)
                yargs = addDockerOption(yargs)
                return yargs
            },
            async (argv) => {
                const mode = argv.release ? '--release' : ''

                const cmd = 'contract build'
                const cmdArgs = `${mode}`

                for(const contract of argv.contract as string[]) {
                    await execCargo(argv, cmd, cmdArgs, `${contractsDir}/${contract}`)
                }
            },
            []
        ).command(
            'test',
            'Test the crates and contracts',
            (yargs) => {
                yargs = addCrateOption(yargs)
                yargs = addContractOption(yargs)
                yargs = addToolchainOption(yargs)
                yargs = addDockerOption(yargs)
                return yargs
            },
            async (argv) => {
                const cmd = 'test'
                const cmdArgs = ''

                await execCargo(argv, cmd, cmdArgs)
            },
            []
        ).command(
            'fmt',
            'Format the crates and contracts',
            (yargs) => {
                yargs = addCrateOption(yargs)
                yargs = addToolchainOption(yargs)
                yargs = addContractOption(yargs)
                yargs = addDockerOption(yargs)
                yargs = yargs.option('check', {
                    type: 'boolean',
                    demand: false,
                    desc: 'Check the code instead of making changes',
                    default: false,
                })
                return yargs
            },
            async (argv) => {
                const cmd = 'fmt'
                const cmdArgs = '--all --verbose ${check}'
                
                await execCargo(argv, cmd, cmdArgs)
            },
            []
        ).command(
            'clippy',
            'Clippy the crates and contracts',
            (yargs) => {
                yargs = addCrateOption(yargs)
                yargs = addToolchainOption(yargs)
                yargs = addContractOption(yargs)
                yargs = addFixOption(yargs)
                yargs = addDockerOption(yargs)
                return yargs
            },
            async (argv) => {
                const fix = argv.fix ? '--fix --allow-dirty --allow-staged' : ''
                
                const cmd = 'clippy'
                const cmdArgs = `${fix} -- -D warnings `

                await execCargo(argv, cmd, cmdArgs)
            },
            []
        )
        .parse();
}

processArgs(process.argv.slice(2))
    .then(() => {
        process.exit(0)
    })
    .catch((error) => {
        console.error(error)
        process.exit(1)
    })