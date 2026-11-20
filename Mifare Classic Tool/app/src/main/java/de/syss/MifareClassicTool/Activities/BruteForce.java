/*
 * Copyright 2013 Gerhard Klostermeier
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


package de.syss.MifareClassicTool.Activities;

import android.app.AlertDialog;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.util.SparseArray;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.widget.AppCompatCheckBox;
import androidx.appcompat.widget.AppCompatEditText;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

import de.syss.MifareClassicTool.Common;
import de.syss.MifareClassicTool.MCReader;
import de.syss.MifareClassicTool.R;

/**
 * Brute force a numeric key range against a MIFARE Classic tag and save the
 * found keys to a key file.
 */
public class BruteForce extends BasicActivity {

    private static final String LOG_TAG = BruteForce.class.getSimpleName();

    private static final int SECTOR_MODE_ALL = 0;
    private static final int SECTOR_MODE_RANGE = 1;
    private static final int SECTOR_MODE_PICK = 2;

    private RadioGroup mKeyTypeGroup;
    private AppCompatEditText mKeyRangeFrom;
    private AppCompatEditText mKeyRangeTo;
    private RadioGroup mSectorModeGroup;
    private LinearLayout mSectorRangeLayout;
    private LinearLayout mSectorPickLayout;
    private final AppCompatCheckBox[] mSectorChecks = new AppCompatCheckBox[40];
    private AppCompatEditText mSectorFrom;
    private AppCompatEditText mSectorTo;
    private int mSectorMode = SECTOR_MODE_ALL;
    private int[] mSelectedSectors;
    private int mSectorTotal;
    private Button mStart;
    private Button mCancel;
    private ProgressBar mProgressBar;
    private TextView mStatus;

    private final Handler mHandler = new Handler(Looper.getMainLooper());
    private MCReader currentReader;
    private boolean mIsRunning = false;
    private int mProgressStatus = -1;
    private int mFirstSector = 0;
    private int mLastSector = -1;
    private int mAuthMode = MCReader.KEY_MAP_MODE_BOTH;
    private String mKeyRangeFromStr = "";
    private String mKeyRangeToStr = "";
    private File mOutputFile;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_brute_force);

        mKeyTypeGroup = findViewById(R.id.radioGroupBruteForceKeyType);
        mKeyRangeFrom = findViewById(R.id.editTextBruteForceKeyRangeFrom);
        mKeyRangeTo = findViewById(R.id.editTextBruteForceKeyRangeTo);
        mSectorModeGroup = findViewById(R.id.radioGroupBruteForceSectorMode);
        mSectorRangeLayout = findViewById(R.id.linearLayoutBruteForceSectorRange);
        mSectorPickLayout = findViewById(R.id.linearLayoutBruteForceSectorPick);
        mSectorFrom = findViewById(R.id.editTextBruteForceSectorFrom);
        mSectorTo = findViewById(R.id.editTextBruteForceSectorTo);
        for (int row = 0; row < 5; row++) {
            LinearLayout rowLayout = new LinearLayout(this);
            rowLayout.setOrientation(LinearLayout.HORIZONTAL);
            for (int col = 0; col < 8; col++) {
                int sector = row * 8 + col;
                AppCompatCheckBox checkBox = new AppCompatCheckBox(this);
                checkBox.setText(String.valueOf(sector));
                LinearLayout.LayoutParams params =
                        new LinearLayout.LayoutParams(
                                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
                rowLayout.addView(checkBox, params);
                mSectorChecks[sector] = checkBox;
            }
            mSectorPickLayout.addView(rowLayout);
        }
        mStart = findViewById(R.id.buttonBruteForceStart);
        mCancel = findViewById(R.id.buttonBruteForceCancel);
        mProgressBar = findViewById(R.id.progressBarBruteForce);
        mStatus = findViewById(R.id.textViewBruteForceStatus);

        mSectorModeGroup.clearCheck();
        ((android.widget.RadioButton) findViewById(
                R.id.radioButtonBruteForceSectorAll)).setChecked(true);
        onSectorModeChanged(null);
    }

    public void onSectorModeChanged(View view) {
        mSectorMode = getSectorMode();
        mSectorRangeLayout.setVisibility(
                mSectorMode == SECTOR_MODE_RANGE ? View.VISIBLE : View.GONE);
        mSectorPickLayout.setVisibility(
                mSectorMode == SECTOR_MODE_PICK ? View.VISIBLE : View.GONE);
        mSectorFrom.setEnabled(mSectorMode == SECTOR_MODE_RANGE);
        mSectorTo.setEnabled(mSectorMode == SECTOR_MODE_RANGE);
    }

    private int getSectorMode() {
        int id = mSectorModeGroup.getCheckedRadioButtonId();
        if (id == R.id.radioButtonBruteForceSectorRange) {
            return SECTOR_MODE_RANGE;
        }
        if (id == R.id.radioButtonBruteForceSectorPick) {
            return SECTOR_MODE_PICK;
        }
        return SECTOR_MODE_ALL;
    }

    private int[] collectCheckedSectors() {
        int[] sectors = new int[mSectorChecks.length];
        int count = 0;
        for (int i = 0; i < mSectorChecks.length; i++) {
            if (mSectorChecks[i].isChecked()) {
                sectors[count++] = i;
            }
        }
        return Arrays.copyOf(sectors, count);
    }

    private int getSelectedKeyMapAuthMode() {
        int checkedId = mKeyTypeGroup.getCheckedRadioButtonId();
        if (checkedId == R.id.radioButtonBruteForceKeyTypeA) {
            return MCReader.KEY_MAP_MODE_KEY_A;
        } else if (checkedId == R.id.radioButtonBruteForceKeyTypeB) {
            return MCReader.KEY_MAP_MODE_KEY_B;
        }
        return MCReader.KEY_MAP_MODE_BOTH;
    }

    public void onStartBruteForce(View view) {
        if (mIsRunning) {
            return;
        }
        mKeyRangeFromStr = mKeyRangeFrom.getText().toString().trim();
        mKeyRangeToStr = mKeyRangeTo.getText().toString().trim();
        long rangeFrom = parseKeyHexLocal(mKeyRangeFromStr);
        long rangeTo = parseKeyHexLocal(mKeyRangeToStr);
        if (rangeFrom < 0 || rangeTo < rangeFrom) {
            Toast.makeText(this, R.string.info_invalid_key_range,
                    Toast.LENGTH_LONG).show();
            return;
        }

        mSectorMode = getSectorMode();
        mSelectedSectors = null;
        if (mSectorMode == SECTOR_MODE_RANGE) {
            int from = parseSectorLocal(mSectorFrom.getText().toString());
            int to = parseSectorLocal(mSectorTo.getText().toString());
            if (from < 0 || to < from) {
                Toast.makeText(this, R.string.info_invalid_sector_range,
                        Toast.LENGTH_LONG).show();
                return;
            }
            mFirstSector = from;
            mLastSector = to;
        } else if (mSectorMode == SECTOR_MODE_PICK) {
            mSelectedSectors = collectCheckedSectors();
            if (mSelectedSectors.length == 0) {
                Toast.makeText(this, R.string.info_invalid_sector_range,
                        Toast.LENGTH_LONG).show();
                return;
            }
            mFirstSector = mSelectedSectors[0];
            mLastSector = mSelectedSectors[mSelectedSectors.length - 1];
        } else {
            mFirstSector = 0;
            mLastSector = -1;
        }
        mAuthMode = getSelectedKeyMapAuthMode();
        showSaveFileDialog();
    }

    private void showSaveFileDialog() {
        final EditText input = new EditText(this);
        input.setInputType(android.text.InputType.TYPE_CLASS_TEXT);
        input.setText("new");
        input.setSelectAllOnFocus(true);
        new AlertDialog.Builder(this)
                .setTitle(R.string.dialog_save_keys_title)
                .setMessage(R.string.dialog_save_keys)
                .setView(input)
                .setPositiveButton(R.string.action_start,
                        (dialog, which) -> {
                            String name = input.getText().toString().trim();
                            mOutputFile = getUniqueKeyFile(name);
                            startBruteForce();
                        })
                .setNegativeButton(R.string.action_cancel, null)
                .show();
    }

    private File getUniqueKeyFile(String baseName) {
        baseName = baseName.trim();
        if (baseName.isEmpty()) {
            baseName = "new";
        }
        baseName = baseName.replaceAll("[^A-Za-z0-9_\\-]", "_");
        if (baseName.isEmpty()) {
            baseName = "new";
        }
        if (baseName.toLowerCase(Locale.US).endsWith(".keys")) {
            baseName = baseName.substring(0, baseName.length() - 5);
        }
        File dir = Common.getFile(Common.KEYS_DIR);
        for (int i = 0; ; i++) {
            String name = i == 0 ? baseName : baseName + i;
            File file = new File(dir, name + ".keys");
            if (!file.exists()) {
                return file;
            }
        }
    }

    private void startBruteForce() {
        MCReader reader = Common.checkForTagAndCreateReader(this);
        currentReader = reader;
        if (reader == null) {
            return;
        }
        if (!reader.setKeyRange(mKeyRangeFromStr, mKeyRangeToStr)) {
            Toast.makeText(this, R.string.info_invalid_key_range,
                    Toast.LENGTH_LONG).show();
            reader.close();
            return;
        }
        if (!reader.setKeyMapAuthMode(mAuthMode)) {
            reader.close();
            return;
        }
        int sectorCount = reader.getSectorCount();
        if (mSectorMode == SECTOR_MODE_ALL) {
            mFirstSector = 0;
            mLastSector = sectorCount - 1;
            mSectorTotal = sectorCount;
            if (!reader.setMappingRange(mFirstSector, mLastSector)) {
                Toast.makeText(this, R.string.info_mapping_sector_out_of_range,
                        Toast.LENGTH_LONG).show();
                reader.close();
                return;
            }
        } else if (mSectorMode == SECTOR_MODE_RANGE) {
            if (mFirstSector < 0 || mLastSector < mFirstSector
                    || mLastSector >= sectorCount) {
                Toast.makeText(this, R.string.info_invalid_sector_range,
                        Toast.LENGTH_LONG).show();
                reader.close();
                return;
            }
            mSectorTotal = mLastSector - mFirstSector + 1;
            if (!reader.setMappingRange(mFirstSector, mLastSector)) {
                Toast.makeText(this, R.string.info_mapping_sector_out_of_range,
                        Toast.LENGTH_LONG).show();
                reader.close();
                return;
            }
        } else {
            for (int sector : mSelectedSectors) {
                if (sector < 0 || sector >= sectorCount) {
                    Toast.makeText(this, R.string.info_invalid_sector_range,
                            Toast.LENGTH_LONG).show();
                    reader.close();
                    return;
                }
            }
            mSectorTotal = mSelectedSectors.length;
            if (!reader.setMappingSectors(mSelectedSectors)) {
                Toast.makeText(this, R.string.info_mapping_sector_out_of_range,
                        Toast.LENGTH_LONG).show();
                reader.close();
                return;
            }
        }

        getWindow().addFlags(
                WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        mProgressStatus = -1;
        mProgressBar.setMax(mSectorTotal);
        mProgressBar.setProgress(0);
        mStatus.setText(R.string.info_brute_force_running);
        mStart.setEnabled(false);
        mIsRunning = true;
        createBruteForceKeyMap(reader);
    }

    private void createBruteForceKeyMap(final MCReader reader) {
        new Thread(() -> {
            int completed = 0;
            while (mProgressStatus < mLastSector) {
                mProgressStatus = reader.buildNextKeyMapPart();
                if (mProgressStatus == -1 || !mIsRunning) {
                    break;
                }
                completed++;
                final int progress = completed;
                mHandler.post(() -> mProgressBar.setProgress(progress));
            }
            mHandler.post(() -> finishBruteForce(reader));
        }).start();
    }

    private void finishBruteForce(MCReader reader) {
        getWindow().clearFlags(
                WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        mProgressBar.setProgress(0);
        mStatus.setText("");
        mStart.setEnabled(true);
        reader.close();
        boolean wasRunning = mIsRunning;
        boolean success = wasRunning && mProgressStatus != -1;
        mIsRunning = false;
        if (success) {
            bruteForceDone(reader);
        } else if (wasRunning && mProgressStatus == -1) {
            Toast.makeText(this, R.string.info_key_map_error,
                    Toast.LENGTH_LONG).show();
        }
    }

    private void bruteForceDone(MCReader reader) {
        SparseArray<byte[][]> keyMap = reader.getKeyMap();
        Set<String> keys = new LinkedHashSet<>();
        if (keyMap != null) {
            for (int i = 0; i < keyMap.size(); i++) {
                byte[][] pair = keyMap.valueAt(i);
                if (pair != null) {
                    if (pair[0] != null) {
                        keys.add(Common.bytes2Hex(pair[0]));
                    }
                    if (pair[1] != null) {
                        keys.add(Common.bytes2Hex(pair[1]));
                    }
                }
            }
        }
        if (keys.isEmpty() || mOutputFile == null) {
            Toast.makeText(this, R.string.info_brute_force_no_keys,
                    Toast.LENGTH_LONG).show();
            return;
        }
        boolean saved = Common.saveFile(mOutputFile,
                keys.toArray(new String[0]), false);
        String title = saved
                ? getString(R.string.info_bruteforce_keys_saved,
                        keys.size(), mOutputFile.getName())
                : getString(R.string.info_strange_error);
        showBruteForceResults(keys, title);
    }

    private void showBruteForceResults(Set<String> keys, String title) {
        StringBuilder sb = new StringBuilder();
        for (String key : keys) {
            sb.append(key).append('\n');
        }
        TextView tv = new TextView(this);
        tv.setTextIsSelectable(true);
        tv.setText(sb.toString());
        int pad = Common.dpToPx(16);
        tv.setPadding(pad, pad, pad, pad);
        ScrollView sv = new ScrollView(this);
        sv.addView(tv);
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setView(sv)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }

    public void onCancelBruteForce(View view) {
        if (mIsRunning) {
            mIsRunning = false;
            if (currentReader != null) {
                currentReader.cancelCreateKeyMap();
            }
            mStatus.setText("");
        } else {
            finish();
        }
    }

    @Override
    public void onBackPressed() {
        if (mIsRunning) {
            onCancelBruteForce(null);
        } else {
            super.onBackPressed();
        }
    }

    private static long parseKeyHexLocal(String hex) {
        if (hex == null) {
            return -1;
        }
        hex = hex.trim();
        if (hex.isEmpty() || hex.length() > 12
                || !hex.matches("[0-9A-Fa-f]+")) {
            return -1;
        }
        try {
            return Long.parseLong(hex, 16);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static int parseSectorLocal(String text) {
        try {
            return Integer.parseInt(text.trim());
        } catch (Exception e) {
            return -1;
        }
    }
}
