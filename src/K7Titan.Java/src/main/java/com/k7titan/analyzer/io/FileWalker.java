package com.k7titan.analyzer.io;

import java.io.IOException;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

public final class FileWalker {

    private FileWalker() {
    }

    public static List<Path> collect(Path target, boolean recurse) throws IOException {
        List<Path> files = new ArrayList<>();
        if (!Files.exists(target)) {
            return files;
        }
        if (Files.isRegularFile(target)) {
            files.add(target);
            return files;
        }
        int maxDepth = recurse ? Integer.MAX_VALUE : 1;
        Files.walkFileTree(target, EnumSet.noneOf(FileVisitOption.class), maxDepth,
                new SimpleFileVisitor<>() {
                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                        if (attrs.isRegularFile()) {
                            files.add(file);
                        }
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFileFailed(Path file, IOException exc) {
                        return FileVisitResult.CONTINUE;
                    }
                });
        return files;
    }
}
