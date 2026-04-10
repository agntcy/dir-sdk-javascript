import { spawnSync } from 'node:child_process';
import { env } from 'node:process';
import { worker } from 'workerpool';

worker({
    pullRecordsBackground,
});

export async function pullRecordsBackground(command: string, commandArgs: string[]) {
    const shell_env = env;

    for (let count = 0; count < 90; count++) {
        // Execute command
        spawnSync(
            command, commandArgs,
            { env: { ...shell_env }, encoding: 'utf8', stdio: 'pipe' },
        );

        await new Promise(resolve => setTimeout(resolve, 1000));
    }
}
